# README

## Introduction

This repository contains code for managing interactions with Verifiable Credentials (VCs) in two different scenarios. The code demonstrates the issuance, storage, presentation, and verification of VCs using a sample implementation.

## Use Cases

### Case 1: Single VC with All Information
In this scenario:
- The University issues a single Verifiable Credential containing the University Name and the 20 groups the student is part of.
- The VC is sent to the student and stored in their wallet.
- An employer requests a presentation to verify the student's role as a TA.
- The student responds with claims via a Presentation Submission.
- The employer verifies the claims and decides whether to grant access.

### Case 2: Linked VC Model
In this scenario:
- The University issues two Verifiable Credentials: one for Identity and one for Membership.
- Both VCs are sent to the student and stored in their wallet.
- An employer requests a presentation to verify if the student graduated from the University.
- The student responds with claims via a Presentation Submission.
- The employer verifies the claims and decides whether to grant access.

## Technologies Used

- Go programming language
- Libraries for Verifiable Credentials, including ssi-sdk
- JSON Web Tokens (JWTs)
- DID (Decentralized Identifiers)
- Cryptography libraries

## Setup Instructions

1. Clone the repository.
2. Install any dependencies required for the code.
3. Set up environment variables, if necessary (e.g., for debugging).
4. Run the main Go file to execute the scenarios.


