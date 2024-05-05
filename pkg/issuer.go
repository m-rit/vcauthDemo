package pkg

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/example"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
)

// BuildSampleIdentityVC Makes a Verifiable Credential using the VC data type using the CredentialBuilder as part of the credentials package in the ssk-sdk.
// It creates a credential with claims of Identity VC which is the Organisation name here
func BuildSampleIdentityVC(signer jwx.Signer, universityDID, recipientDID string) (credID string, cred string, err error) {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := universityDID
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]any{
		"id": recipientDID, // did:<method-name>:<method-specific-id>
		"alumniOf": map[string]any{ // claims are here
			"id": recipientDID,
			"name": []any{
				map[string]any{"value": "XYZ University",
					"lang": "en",
				},
			},
		},
	}

	// For more information on VC object, go to:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/model.go
	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID, // credential id
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	if err := knownCred.IsValid(); err != nil {
		return "", "", err
	}

	dat, err := json.Marshal(knownCred)
	if err != nil {
		return "", "", err
	}
	logrus.Debug(string(dat))

	// sign the credential as a JWT
	signedCred, err := credential.SignVerifiableCredentialJWT(signer, knownCred)
	if err != nil {
		return "", "", err
	}
	cred = string(signedCred)
	_, credToken, _, err := credential.ParseVerifiableCredentialFromJWT(string(signedCred))
	if err != nil {
		return "", "", err
	}
	credID = credToken.JwtID()

	example.WriteNote(fmt.Sprintf("VC issued from %s to %s", universityDID, recipientDID))

	return credID, cred, nil
}

// BuildCombinedVC Makes a Verifiable Credential using the VC data type using the CredentialBuilder as part of the credentials package in the ssk-sdk.
// It creates a credential with claims of Organisation name and all the groups that User is part of here/
// In the demo, 20 groups are added in the VC
func BuildCombinedVC(signer jwx.Signer, universityDID, recipientDID string) (credID string, cred string, err error) {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := universityDID
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]any{
		"id": recipientDID, // did:<method-name>:<method-specific-id>
		"alumniOf": map[string]any{ // claims are here
			"id": recipientDID,
			"name": []any{
				map[string]any{"value": "Example University",
					"lang": "en",
				},
			},
			"roles": []any{
				map[string]any{"value": "Teaching Assistant",
					"lang": "en",
				}, map[string]any{
					"value": "Hiking Group",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group1",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group2",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group3",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group5",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group6",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group2",
					"lang":  "fr",
				}, map[string]any{
					"value": "Group3",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group5",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group6",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group2",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group3",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group5",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group6",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group2",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group3",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group5",
					"lang":  "fr",
				}, map[string]any{
					"value": "Hiking Group6",
					"lang":  "fr",
				},
			},
		},
	}

	// For more information on VC object, go to:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/model.go
	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID, // credential id
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	if err := knownCred.IsValid(); err != nil {
		return "", "", err
	}

	dat, err := json.Marshal(knownCred)
	if err != nil {
		return "", "", err
	}
	logrus.Debug(string(dat))

	// sign the credential as a JWT
	signedCred, err := credential.SignVerifiableCredentialJWT(signer, knownCred)
	if err != nil {
		return "", "", err
	}
	cred = string(signedCred)
	_, credToken, _, err := credential.ParseVerifiableCredentialFromJWT(string(signedCred))
	if err != nil {
		return "", "", err
	}
	credID = credToken.JwtID()

	example.WriteNote(fmt.Sprintf("VC issued from %s to %s", universityDID, recipientDID))

	return credID, cred, nil
}

// BuildMembershipVC  Makes a Verifiable Credential using the VC data type using the CredentialBuilder as part of the credentials package
// It creates a credential with claims of group name that the user is part of.
func BuildMembershipVC(signer jwx.Signer, universityDID, recipientDID string) (credID string, cred string, err error) {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/18723"
	knownType := []string{"VerifiableCredential", "AlumniMemberCredential"}
	knownIssuer := universityDID
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]any{
		"IdentityReference": map[string]any{ // claims are here
			"id": recipientDID,
			"roles": []any{
				map[string]any{"value": "Teaching Assistant",
					"lang": "en",
				},
			},
		},
	}

	// For more information on VC object, go to:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/model.go
	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	if err := knownCred.IsValid(); err != nil {
		return "", "", err
	}

	dat, err := json.Marshal(knownCred)
	if err != nil {
		return "", "", err
	}
	logrus.Debug(string(dat))

	// sign the credential as a JWT
	signedCred, err := credential.SignVerifiableCredentialJWT(signer, knownCred)
	if err != nil {
		return "", "", err
	}
	cred = string(signedCred)
	_, credToken, _, err := credential.ParseVerifiableCredentialFromJWT(string(signedCred))
	if err != nil {
		return "", "", err
	}
	credID = credToken.JwtID()

	example.WriteNote(fmt.Sprintf("VC issued from %s to %s", universityDID, recipientDID))

	return credID, cred, nil
}
