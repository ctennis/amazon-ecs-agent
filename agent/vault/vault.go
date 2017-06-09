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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	
	//"github.com/cihub/seelog"

	"github.com/hashicorp/vault/api"
)

func apiClient(creds *credentials.Credentials) (*api.Client, error) {
    _, exists := os.LookupEnv("VAULT_ADDR")

    if(!exists) {
        return nil, fmt.Errorf("VAULT_ADDR not set, cannot contact vault %#v", os.Environ())
    }
    
	apiclient, err := api.NewClient(nil)

	if err != nil {
		return nil, fmt.Errorf("ERROR getting vault apiclient")
	}
	
	err = auth(apiclient, creds)
	    
	if err != nil {
	    return nil, fmt.Errorf("Error in vault auth")
	}

    return apiclient, nil
}

func auth(c *api.Client, creds *credentials.Credentials) (error) {

    stsSession := session.New(&aws.Config{Credentials: creds})
 
	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	// Inject the required auth header value, if supplied, and then sign the request including that header
	stsRequest.Sign()

	// Now extract out the relevant parts of the request
	headersJson, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return err
	}
	method := stsRequest.HTTPRequest.Method
	targetUrl := base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	headers := base64.StdEncoding.EncodeToString(headersJson)
	body := base64.StdEncoding.EncodeToString(requestBody)

	// And pass them on to the Vault server
	secret, err := c.Logical().Write("auth/aws/login", map[string]interface{}{
		"iam_http_request_method": method,
		"iam_request_url":         targetUrl,
		"iam_request_headers":     headers,
		"iam_request_body":        body,
	})

	if err != nil {
		return err
	}
	
	if secret == nil {
		return fmt.Errorf("empty response from credential provider")
	}
	
	c.SetToken(secret.Auth.ClientToken) 
	return nil
}


func SubstituteSecrets(envVars map[string]string, creds *credentials.Credentials) (map[string]string, error) {
    c, err := apiClient(creds)

    if err != nil {
        return envVars, err
    }

    //seelog.Errorf("TEST: IN SUBSITUTE SECRETS %v", envVars)

	r, _ := regexp.Compile("^vault://(.+)")

	for varName, varValue := range envVars {
		if(r.MatchString(varValue)) {
		
			valStripped := strings.TrimLeft(varValue, "vault://")

			result2 := strings.Split(valStripped, ":")
			vaultLoc   := result2[0]
			vaultField := result2[1]

			sec, err := c.Logical().Read(vaultLoc)

            if(err != nil) {
                return nil, fmt.Errorf("Error %v looking up %v", err, vaultLoc)
            }
            
            newVal := sec.Data[vaultField]

            envVars[varName] = fmt.Sprintf("%v", newVal)

		}
	}

	return envVars, nil
   
}

