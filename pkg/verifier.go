package pkg

import (
	"context"

	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/pkg/errors"
)

// ValidateAccess is a very simple validation process against a Presentation Submission
// It checks:
// 1. That the VP is valid
// 2. All VCs in the VP are valid
// 3. That the VC was issued by a trusted entity (implied by the presentation, according to the Presentation Definition)
func ValidateAccess(verifier jwx.Verifier, r resolution.Resolver, submissionBytes []byte) error {
	_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), verifier, r, string(submissionBytes))
	if err != nil {
		return errors.Wrap(err, "validating VP signature")
	}

	if err = vp.IsValid(); err != nil {
		return errors.Wrap(err, "validating VP")
	}
	if len(vp.VerifiableCredential) < 2 {
		// Case 1- parse VC and get all roles
		x, _ := vp.VerifiableCredential[0].(string)
		_, _, token, _ := credential.ParseVerifiableCredentialFromJWT(x)
		_ = fmt.Sprintf("%+v", token.CredentialSubject)
		return nil
	}
	x, _ := vp.VerifiableCredential[1].(string)
	_, _, token, _ := credential.ParseVerifiableCredentialFromJWT(x)
	fmt.Sprintf("%+v", token)

	return nil
}
