package vault

import (
	"testing"
)

func TestVaultEnvUrlParsing(t *testing.T) {
	val, _ := parseSecret("vault://cloudbees/secret/foo/blah:val")
	if (val != secretEnvVar{"vault", "cloudbees", "secret/foo/blah", "val"}) {
		t.Errorf("error parsing secret %v", val)
	}
}
