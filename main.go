package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential"
	"os"

	"github.com/sirupsen/logrus"

	emp "didTest/pkg"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/peer"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/example"
	"time"
)

// Set to debug mode here
var debug = os.Getenv("DEBUG")

const (
	DebugMode = "1"
)

// set mode for debugging
// in bash:
// export DEBUG=1
func init() {
	//debug = "1"
	if debug == DebugMode {
		println("Debug mode")
		logrus.SetLevel(logrus.DebugLevel)
	}
}

// main runs two the authentication interaction in two cases :
//case 1 - single VC with 20 groups and case 2- Linked VC
func main() {
	
	// Case 1 : Using one VC with all the information
	// Univeristy Issues 1 Credentials (containing Univeristy Name and the 20 groups user is part of)
	// Case 2 : Using Linked VC Model
	// Univeristy Issues 2 Credentials (one with Idenitity VC and one with MembershipVC)
	var t1, t2, t3, t4 time.Duration
	var size1, size2, size3, psize1, psize2 int
	example.WriteNote("------------Case1")
	{
		step := 0

		example.WriteStep("Starting University Flow", step)
		step++
		start := time.Now()

		// Wallet initialization
		example.WriteStep("Initializing Student", step)
		step++

		student, err := emp.NewEntity("Student", did.KeyMethod)
		example.HandleExampleError(err, "failed to create student")
		studentDID := student.GetWallet().GetDIDs()[0]
		studentKeys, err := student.GetWallet().GetKeysForDID(studentDID)
		studentKey := studentKeys[0].Key
		studentKID := studentKeys[0].ID
		example.HandleExampleError(err, "failed to get student key")

		example.WriteStep("Initializing Employer", step)
		step++

		employer, err := emp.NewEntity("Employer", "peer")
		example.HandleExampleError(err, "failed to make employer identity")
		employerDID := employer.GetWallet().GetDIDs()[0]
		employerKeys, err := employer.GetWallet().GetKeysForDID(employerDID)
		employerKey := employerKeys[0].Key
		employerKID := employerKeys[0].ID
		example.HandleExampleError(err, "failed to get employer key")

		example.WriteStep("Initializing University", step)
		step++

		university, err := emp.NewEntity("University", did.PeerMethod)
		example.HandleExampleError(err, "failed to create university")
		universityDID := university.GetWallet().GetDIDs()[0]
		universityKeys, err := university.GetWallet().GetKeysForDID(universityDID)
		universityKey := universityKeys[0].Key
		universityKID := universityKeys[0].ID
		example.HandleExampleError(err, "failed to get university key")

		example.WriteNote(fmt.Sprintf("Initialized University (Verifier) DID: %s and registered it", universityDID))

		example.WriteStep("Example University Creates VC for Holder", step)
		step++

		universitySigner, err := jwx.NewJWXSigner(universityDID, universityKID, universityKey)
		example.HandleExampleError(err, "failed to build university signer")

		vcID, vc, err := emp.BuildSingleVC(*universitySigner, universityDID, studentDID)
		example.HandleExampleError(err, "failed to build vc")

		example.WriteStep("Example University Sends VC to Student (Holder)", step)
		step++
        size1 = len(vc)   
		err = student.GetWallet().AddCredentialJWT(vcID, vc)
		example.HandleExampleError(err, "failed to add credentials to wallet")

		msg := fmt.Sprintf("VC is stored in wallet. Wallet size is now: %d", student.GetWallet().Size())
		example.WriteNote(msg)

		example.WriteNote(fmt.Sprintf("initialized Employer (Verifier) DID: %v", employerDID))
		example.WriteStep("Verifier wants to verify student role as TA. Sends a presentation request", step)
		step++

		presentationData, err := emp.MakePresentationData("test-id", "id-1", universityDID)
		example.HandleExampleError(err, "failed to create pd")

		dat, err := json.Marshal(presentationData)
		example.HandleExampleError(err, "failed to marshal presentation data")
		logrus.Debugf("Presentation Data:\n%v", string(dat))

		presentationRequestJWT, employerSigner, err := emp.MakePresentationRequest(employerKey, employerKID, presentationData, employerDID, studentDID)
		example.HandleExampleError(err, "failed to make presentation request")

		studentSigner, err := jwx.NewJWXSigner(studentDID, studentKID, studentKey)
		example.HandleExampleError(err, "failed to build json web key signer")

		example.WriteNote("Student returns claims via a Presentation Submission")

		employerVerifier, err := employerSigner.ToVerifier(studentDID)
		example.HandleExampleError(err, "failed to build employer verifier")
		submission, err := emp.BuildPresentationSubmission(string(presentationRequestJWT), *employerVerifier, *studentSigner, vc)
		example.HandleExampleError(err, "failed to build presentation submission")

		verifier, err := studentSigner.ToVerifier(employerDID)
		example.HandleExampleError(err, "failed to construct verifier")

		r, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}, peer.Resolver{}}...)
		example.HandleExampleError(err, "failed to create DID r")
		_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), *verifier, r, string(submission))
		example.HandleExampleError(err, "failed to verify jwt")

		dat, err = json.Marshal(vp)
		psize1 = len(dat)
		example.HandleExampleError(err, "failed to marshal submission")
		tokenSize := len(dat)
		logrus.Debugf("Submission:\n%v", string(dat))
		logrus.Debugf("lenght:\n%v", tokenSize)
		startverify := time.Now()
		example.WriteStep("Employer Attempting to Grant Access", step)
		if err = emp.ValidateAccess(*verifier, r, submission); err == nil {
			example.WriteOK("Access Granted!")
		} else {
			example.WriteError(fmt.Sprintf("Access was not granted! Reason: %s", err))
		}
		t3 = time.Since(startverify)
		t4 = time.Since(start)
		

	}
	
	example.WriteNote("------------Case2")
	
	{
		step := 0

		example.WriteStep("Starting University Flow", step)
		step++

		// Wallet initialization
		example.WriteStep("Initializing Student", step)
		step++
		start := time.Now()
		student, err := emp.NewEntity("Student", did.KeyMethod)
		example.HandleExampleError(err, "failed to create student")
		studentDID := student.GetWallet().GetDIDs()[0]                    //local
		studentKeys, err := student.GetWallet().GetKeysForDID(studentDID) //local
		studentKey := studentKeys[0].Key
		studentKID := studentKeys[0].ID
		example.HandleExampleError(err, "failed to get student key")

		example.WriteStep("Initializing Employer", step)
		step++

		employer, err := emp.NewEntity("Employer", "peer")
		example.HandleExampleError(err, "failed to make employer identity")
		employerDID := employer.GetWallet().GetDIDs()[0]                     // from personal wallet
		employerKeys, err := employer.GetWallet().GetKeysForDID(employerDID) //from personal wallet
		employerKey := employerKeys[0].Key
		employerKID := employerKeys[0].ID
		example.HandleExampleError(err, "failed to get employer key")

		example.WriteStep("Initializing University", step)
		step++

		university, err := emp.NewEntity("University", did.PeerMethod)
		example.HandleExampleError(err, "failed to create university")
		universityDID := university.GetWallet().GetDIDs()[0]
		universityKeys, err := university.GetWallet().GetKeysForDID(universityDID)
		universityKey := universityKeys[0].Key
		universityKID := universityKeys[0].ID
		example.HandleExampleError(err, "failed to get university key")

		example.WriteNote(fmt.Sprintf("Initialized University (Verifier) DID: %s and registered it", universityDID))

		example.WriteStep("Example University Creates Identity-VC for Holder", step)
		step++

		universitySigner, err := jwx.NewJWXSigner(universityDID, universityKID, universityKey)
		example.HandleExampleError(err, "failed to build university signer")
		vcID, vc, err := emp.BuildSampleIdentityVC(*universitySigner, universityDID, studentDID)
		example.HandleExampleError(err, "failed to build vc")

		example.WriteStep("Example University Sends VC to Student (Holder)", step)
		step++

		err = student.GetWallet().AddCredentialJWT(vcID, vc)
		example.HandleExampleError(err, "failed to add credentials to wallet")
        size2 = len(vc)
		msg := fmt.Sprintf("VC is stored in wallet. Wallet size is now: %d", student.GetWallet().Size())
		example.WriteNote(msg)

		// adding membership
		example.WriteStep("Example University Creates MembershipVC for Holder", step)
		step++

		vcID2, vc2, err2 := emp.BuildMembershipVC(*universitySigner, universityDID, studentDID)
		example.HandleExampleError(err2, "failed to build vc")
        size3 = len(vc2)
		example.WriteStep("Example University Sends VC to Student (Holder)", step)
		step++

		err = student.GetWallet().AddCredentialJWT(vcID2, vc2)
		example.HandleExampleError(err, "failed to add credentials to wallet")

		msg2 := fmt.Sprintf("VC is stored in wallet. Wallet size is now: %d", student.GetWallet().Size())
		example.WriteNote(msg2)

		example.WriteNote(fmt.Sprintf("initialized Employer (Verifier) DID: %v", employerDID))
		example.WriteStep("Employer wants to verify student graduated from Example University. Sends a presentation request", step)
		step++

		presentationData, err := emp.MakeCombinedPresentationData("test-id", "id-1", "id-2", universityDID)
		example.HandleExampleError(err, "failed to create pd")
		dat, err := json.Marshal(presentationData)
		psize2 =         len(dat)  

		example.HandleExampleError(err, "failed to marshal presentation data")
		logrus.Debugf("Presentation Data:\n%v", string(dat))

		presentationRequestJWT, employerSigner, err := emp.MakePresentationRequest(employerKey, employerKID, presentationData, employerDID, studentDID)
		example.HandleExampleError(err, "failed to make presentation request")

		studentSigner, err := jwx.NewJWXSigner(studentDID, studentKID, studentKey)
		example.HandleExampleError(err, "failed to build json web key signer")

		example.WriteNote("Student returns claims via a Presentation Submission")

		employerVerifier, err := employerSigner.ToVerifier(studentDID)
		example.HandleExampleError(err, "failed to build employer verifier")
		submission, err := emp.BuildCombinedPresentationSubmission(string(presentationRequestJWT), *employerVerifier, *studentSigner, vc, vc2)
		example.HandleExampleError(err, "failed to build presentation submission")

		verifier, err := studentSigner.ToVerifier(employerDID)
		example.HandleExampleError(err, "failed to construct verifier")

		r, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}, peer.Resolver{}}...)
		example.HandleExampleError(err, "failed to create DID r")
		_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), *verifier, r, string(submission))
		example.HandleExampleError(err, "failed to verify jwt")

		dat, err = json.Marshal(vp)
		example.HandleExampleError(err, "failed to marshal submission")
		logrus.Debugf("Submission:\n%v", string(dat))
		tokenSize := len(dat)
		logrus.Debugf("length:\n%v", tokenSize)
		startverify := time.Now()
		example.WriteStep(fmt.Sprintf("Employer Attempting to Grant Access"), step)
		if err = emp.ValidateAccess(*verifier, r, submission); err == nil {
			example.WriteOK("Access Granted!")
		} else {
			example.WriteError(fmt.Sprintf("Access was not granted! Reason: %s", err))
		}
		t1 = time.Since(startverify)
		t2 = time.Since(start)
		

	}
	fmt.Println("Time Taken--------------------")
	fmt.Println("time taken to verify took in 1st case : ", t1)
	fmt.Println("total time taken in 1st Case :", t2)
	fmt.Println("time taken to verify took in 2nd case :", t3)
	fmt.Println("total time taken in 2nd Case :", t4)
    
	fmt.Println("VC sizes--------------------")
	fmt.Println ("VC size in 1st case - single VC with 20 groups:", size1)
	fmt.Println ("VC size in 2nd case - identity VC:", size2)
	fmt.Println ("VC size in 2nd case - 1 membership VC:", size3)

	fmt.Println("Presentation sizes.............. ")
	fmt.Println("Presentation size in case 1 (single VC with 20 groups) :", psize1)
    fmt.Println("Presentation size in case 2 (linked VC) :", psize2)

	
}
