//go:build awskms

package envelope

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMS wraps per-object keys with a symmetric key in AWS KMS. The wrapping
// key never leaves KMS; every wrap and unwrap is one API call, recorded in
// CloudTrail. The row identity goes along as the encryption context, which
// KMS enforces on decrypt. Built only with -tags awskms, so the default
// binary carries no AWS SDK.
type AWSKMS struct {
	key    string
	client *kms.Client
}

// NewAWSKMS uses the standard AWS credential and region chain. endpoint
// overrides the API endpoint, for local emulators and tests.
func NewAWSKMS(ctx context.Context, key, endpoint string) (Wrapper, error) {
	if key == "" {
		return nil, errors.New("envelope: AWS KMS key id is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(cfg, func(o *kms.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return &AWSKMS{key: key, client: client}, nil
}

// ID names the KMS key as configured: an id, an ARN or an alias.
func (a *AWSKMS) ID() string { return "awskms:" + a.key }

// Wrap encrypts dek under the KMS key, bound to aad through the encryption context.
func (a *AWSKMS) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	out, err := a.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             aws.String(a.key),
		Plaintext:         dek,
		EncryptionContext: encryptionContext(aad),
	})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

// Unwrap is the inverse of Wrap. A blob that KMS rejects, tampered or
// presented with another row's context, is ErrOpen.
func (a *AWSKMS) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	out, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:             aws.String(a.key),
		CiphertextBlob:    wrapped,
		EncryptionContext: encryptionContext(aad),
	})
	if err != nil {
		var invalid *types.InvalidCiphertextException
		if errors.As(err, &invalid) {
			return nil, ErrOpen
		}
		return nil, err
	}
	return out.Plaintext, nil
}

func encryptionContext(aad []byte) map[string]string {
	return map[string]string{"sealbox": hex.EncodeToString(aad)}
}
