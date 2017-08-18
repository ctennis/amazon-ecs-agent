package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/cihub/seelog"

	"github.com/hashicorp/vault/api"
)

type secretEnvVar struct {
	proto  string
	host   string
	secret string
	field  string
}

var secretMatchRegexp, _ = regexp.Compile("^(\\w+)://(.*?)/(.+)")

func parseSecret(value string) (secretEnvVar, error) {

	v := secretMatchRegexp.FindStringSubmatch(value)

	if v != nil {
		var proto = v[1]
		var host = v[2]
		var splitStrings = strings.Split(v[3], ":")

		var secret = splitStrings[0]
		var field = splitStrings[1]

		return secretEnvVar{proto, host, secret, field}, nil
	}

	return secretEnvVar{}, fmt.Errorf("Secret %v parse error", value)
}

func apiClient() *api.Client {

	_, exists := os.LookupEnv("VAULT_ADDR")
	if !exists {
		return nil
	}

	client, err := api.NewClient(nil)

	if err != nil {
		seelog.Error(err)
	}

	return client
}

func auth(c *api.Client, creds *credentials.Credentials, vaultRole string) error {
	if c == nil {
		return fmt.Errorf("[vault] api client is nil")
	}

	stsSession := session.New(&aws.Config{Credentials: creds})

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	// Inject the required auth header value, if supplied, and then sign the request including that header
	stsRequest.Sign()

	// Now extract out the relevant parts of the request
	headersJSON, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return err
	}
	method := stsRequest.HTTPRequest.Method
	targetURL := base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	headers := base64.StdEncoding.EncodeToString(headersJSON)
	body := base64.StdEncoding.EncodeToString(requestBody)

	// And pass them on to the Vault server
	secret, err := c.Logical().Write("auth/aws/login", map[string]interface{}{
		"iam_http_request_method": method,
		"iam_request_url":         targetURL,
		"iam_request_headers":     headers,
		"iam_request_body":        body,
                "role":                    vaultRole,
	})

	if err != nil {
		return err
	}

	if secret == nil {
		return fmt.Errorf("[vault] - empty response from credential provider")
	}

	c.SetToken(secret.Auth.ClientToken)
	return nil
}

// SubstituteSecrets takes a map of environment variables/values and attempts to find any
// values with vault looking URLS (e.g.: vault://url/secret/blah/foo:field), and will
// connect to a vault server to replace that value with the actual secret
//
// Errors are attempted to be handled gracefully by just not substituting the value.
func SubstituteSecrets(envVars map[string]string, creds *credentials.Credentials) (returnVars map[string]string, ferr error) {

	// Check to make sure we have any secrets we need to do anything with

	var needToAuth = false;

	for _, vv := range envVars {
               match, _ := regexp.MatchString("^vault://", vv)
                if !match {
                        continue
                }
		needToAuth = true
		break
	}

	if(!needToAuth) {
		return envVars, nil
	}

	c := apiClient()

	if c == nil {
		return envVars, fmt.Errorf("[vault] - Unable to get vault api client")
	}

	err := auth(c, creds, envVars["vault_role"])

	if err != nil {
		return envVars, err
	}

	for varName, varValue := range envVars {

		match, _ := regexp.MatchString("^vault://", varValue)
		if !match {
			continue
		}

		var envVar, err = parseSecret(varValue)

		if err != nil {
			ferr = fmt.Errorf("[vault] - error parsing secret %v: %v", varValue, err)
			seelog.Errorf("%v", ferr)
			continue
		}

		sec, err := c.Logical().Read(envVar.secret)

		if err != nil {
			ferr = fmt.Errorf("[vault] - error reading %v: %v", envVar.secret, err)
			seelog.Errorf("%v", ferr)
			continue
		}

		if sec == nil {
			ferr = fmt.Errorf("[vault] - secret not found: %v", envVar.secret)
			seelog.Errorf("%v", ferr)
			continue
		}

		newVal, ok := sec.Data[envVar.field]
		if(ok) {
			envVars[varName] = fmt.Sprintf("%v", newVal)
		} else {
			ferr = fmt.Errorf("[vault] - field %v not found in secret %v", envVar.field, envVar.secret)
			seelog.Errorf("%v", ferr)
		}

	}

	return envVars, ferr

}
