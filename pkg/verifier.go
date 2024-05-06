package pkg

import (
	"context"
	"reflect"

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
	m := map[string]any{"value": "Teaching Assistant",
	"lang": "en",
} 
	_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), verifier, r, string(submissionBytes))
	if err != nil {
		return errors.Wrap(err, "validating VP signature")
	}

	if err = vp.IsValid(); err != nil {
		return errors.Wrap(err, "validating VP")
	}
	if len(vp.VerifiableCredential) < 2 {
		// Case 1 - parse VC and get all roles and check  if 'Teaching assistant role' exists
		x, _ := vp.VerifiableCredential[0].(string)
		_, _, token, _ := credential.ParseVerifiableCredentialFromJWT(x)
		for _, obj :=  range(token.CredentialSubject){
			y, ok := obj.([]interface{})
			if ok {
             for _, elem := range(y) {
				eq := reflect.DeepEqual(elem, m)
				if eq {
					return nil // we found the required role from the list
				}
			 }
			return errors.Wrap(err, "validating VP")
			}
		}
		return nil
	}
	// case 2 - parse the VC and get the one role in the membership VC
	x, _ := vp.VerifiableCredential[1].(string)
	_, _, token, _ := credential.ParseVerifiableCredentialFromJWT(x)
	for _, obj :=  range(token.CredentialSubject){
		y, ok := obj.(map[string]interface{})
		if ok {
			z, _ := y["roles"].([]interface{})
			eq := reflect.DeepEqual(z[0],m)
				if eq {
					return nil // we found the required role from the list
				}
		    return errors.Wrap(err, "validating VP")
		}
	}
	return errors.Wrap(err, "validating VP")
}
