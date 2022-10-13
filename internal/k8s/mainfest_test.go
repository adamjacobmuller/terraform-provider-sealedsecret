package k8s

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateSecret(t *testing.T) {
	secretKey, secretValue := "secret", "secret_aaa"
	tests := []struct {
		Name              string
		Input             SecretManifest
		ExpectedDataValue string
		ExpectedErr       error
	}{
		{
			Name: "happy day",
			Input: SecretManifest{
				Name:       "name_aaa",
				Namespace:  "ns_aaa",
				Type:       "type_aaa",
				Data:       map[string]interface{}{secretKey: secretValue},
				StringData: map[string]string{secretKey: secretValue},
			},
			ExpectedDataValue: secretValue,
			ExpectedErr:       nil,
		},
		{
			Name: "only data",
			Input: SecretManifest{
				Name:      "name_aaa",
				Namespace: "ns_aaa",
				Type:      "type_aaa",
				Data:      map[string]interface{}{secretKey: secretValue},
			},
			ExpectedDataValue: secretValue,
			ExpectedErr:       nil,
		},
		{
			Name: "only stringData",
			Input: SecretManifest{
				Name:       "name_aaa",
				Namespace:  "ns_aaa",
				Type:       "type_aaa",
				StringData: map[string]string{secretKey: secretValue},
			},
			ExpectedDataValue: "",
			ExpectedErr:       nil,
		},
		{
			Name:        "no data should result in error",
			Input:       SecretManifest{},
			ExpectedErr: ErrEmptyData,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			secret, err := CreateSecret(&tc.Input)

			assert.Equal(t, tc.ExpectedErr, err)
			assert.Equal(t, tc.Input.Name, secret.Name)
			assert.Equal(t, tc.Input.Namespace, secret.Namespace)
			assert.Equal(t, tc.Input.Type, string(secret.Type))
			assert.Equal(t, tc.ExpectedDataValue, string(secret.Data[secretKey]))
			assert.Equal(t, tc.Input.StringData[secretKey], secret.StringData[secretKey])
		})
	}

}
