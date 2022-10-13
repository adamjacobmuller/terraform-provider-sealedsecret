package k8s

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"html/template"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

const secretManifestTmpl = `
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: {{ .Name }}
  namespace: {{ .Namespace }}
{{ if .Data }}
data:
  {{- range $key, $value := .Data }}
  {{ $key }}: {{ $value -}}
  {{ end }}
{{ end }}
{{ if .StringData }}
stringData:
  {{- range $key, $value := .StringData }}
  {{ $key }}: {{ $value -}}
  {{ end }}
{{ end }}
type: {{ .Type }}`

type SecretManifest struct {
	Name       string
	Namespace  string
	Type       string
	Data       map[string]interface{}
	StringData map[string]string
}

var ErrEmptyData = errors.New("secret manifest Data and StringData cannot be empty")

func CreateSecret(sm *SecretManifest) (v1.Secret, error) {
	if len(sm.Data) == 0 && len(sm.StringData) == 0 {
		return v1.Secret{}, ErrEmptyData
	}

	// if it is a .docker/config.json file then the data should already be base64 encoded
	if sm.Type != "kubernetes.io/dockerconfigjson" {
		sm.Data = b64EncodeMapValue(sm.Data)
	}
	secretManifestYAML := new(bytes.Buffer)

	t, err := template.New("secretManifestTmpl").Parse(secretManifestTmpl)
	if err != nil {
		return v1.Secret{}, err
	}
	if err := t.Execute(secretManifestYAML, sm); err != nil {
		return v1.Secret{}, err
	}

	var secret v1.Secret
	if err := runtime.DecodeInto(scheme.Codecs.UniversalDecoder(), secretManifestYAML.Bytes(), &secret); err != nil {
		return v1.Secret{}, err
	}

	return secret, nil
}

func b64EncodeMapValue(m map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{}
	for key, value := range m {
		result[key] = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v", value)))
	}
	return result
}
