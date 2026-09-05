//go:build !awskms

package envelope

import (
	"context"
	"errors"
)

// NewAWSKMS is available only in binaries built with -tags awskms; the
// default build carries no AWS SDK.
func NewAWSKMS(context.Context, string, string) (Wrapper, error) {
	return nil, errors.New("envelope: this binary was built without AWS KMS support: build with -tags awskms")
}
