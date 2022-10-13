package kubeseal

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/AdamJacobMuller/terraform-provider-sealedsecret/internal/k8s"
	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/cert"
)

type PKResolverFunc = func(ctx context.Context) (*rsa.PublicKey, error)

func FetchPK(c k8s.Clienter, controllerName, controllerNamespace string) PKResolverFunc {
	doReq := func(ctx context.Context) (*rsa.PublicKey, error) {
		resp, err := c.Get(ctx, controllerName, controllerNamespace, "/v1/cert.pem")
		if err != nil {
			return nil, err
		}
		certs, err := cert.ParseCertsPEM(resp)
		if err != nil {
			return nil, err
		}

		pk, ok := certs[0].PublicKey.(*rsa.PublicKey)
		if !ok {
			err = fmt.Errorf("expected public key, got: %v", certs[0].PublicKey)
		}
		return pk, nil
	}

	var publicKey *rsa.PublicKey
	var err error

	return func(ctx context.Context) (*rsa.PublicKey, error) {
		if err != nil && k8sErrors.IsNotFound(err) || k8sErrors.IsServiceUnavailable(err) {
			publicKey, err = doReq(ctx)
		}
		if publicKey == nil && err == nil {
			publicKey, err = doReq(ctx)
		}
		return publicKey, err
	}
}

func SealSecret(secret v1.Secret, pk *rsa.PublicKey) ([]byte, error) {
	codecs := scheme.Codecs

	// Strip read-only server-side ObjectMeta (if present)
	secret.SetSelfLink("")
	secret.SetUID("")
	secret.SetResourceVersion("")
	secret.Generation = 0
	secret.SetCreationTimestamp(metav1.Time{})
	secret.SetDeletionTimestamp(nil)
	secret.DeletionGracePeriodSeconds = nil

	sealedSecret, err := ssv1alpha1.NewSealedSecret(codecs, pk, &secret)
	if err != nil {
		return nil, fmt.Errorf("unable to seal secret: %w", err)
	}

	prettyEnc, err := prettyEncoder(codecs, runtime.ContentTypeYAML, ssv1alpha1.SchemeGroupVersion)
	if err != nil {
		return nil, err
	}
	encodedSealedSecret, err := runtime.Encode(prettyEnc, sealedSecret)
	if err != nil {
		return nil, err
	}
	return encodedSealedSecret, nil
}

func prettyEncoder(codecs runtimeserializer.CodecFactory, mediaType string, gv runtime.GroupVersioner) (runtime.Encoder, error) {
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		return nil, fmt.Errorf("binary can't serialize %s", mediaType)
	}

	prettyEncoder := info.PrettySerializer
	if prettyEncoder == nil {
		prettyEncoder = info.Serializer
	}

	enc := codecs.EncoderForVersion(prettyEncoder, gv)
	return enc, nil
}
