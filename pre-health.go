package main

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"time"
)

type SmartContract struct {
	contractapi.Contract
}

// HealthRecord corresponds to the data stored after Alg 4
type HealthRecord struct {
	RecordID           string `json:"recordID"`
	PatientID          string `json:"patientID"`      // The patient's unique Fabric identity
	ProviderID         string `json:"providerID"`     // The provider's Fabric identity who stored it
	CiphertextLocation string `json:"ciphertextLocation"` // Location of C_Pi
	PatientPublicKey   string `json:"patientPublicKey"`   // The patient's pk_Pi from OpenFHE
}

// SharingRequest corresponds to the request created in Alg 5, line 4
type SharingRequest struct {
	RequestID  string `json:"requestID"`
	RecordID   string `json:"recordID"`
	RequesterID string `json:"requesterID"` // The requester's (e.g., insurance) Fabric ID
	PatientID  string `json:"patientID"`
	Status     string `json:"status"` // e.g., "PENDING", "APPROVED"
}

// SharingEvent corresponds to the log created in Alg 5, line 12
type SharingEvent struct {
	EventID           string `json:"eventID"`
	RecordID          string `json:"recordID"`
	PatientID         string `json:"patientID"`
	RequesterID       string `json:"requesterID"`
	SharingProviderID string `json:"sharingProviderID"` // The Provider who acted as proxy
	Timestamp         string `json:"timestamp"`
	CiphertextHash    string `json:"ciphertextHash"` // Hash of C'_Pi
}

// StoreHealthRecord implements the on-chain logic for Algorithm 4.
// It is called by the Healthcare Provider after they have encrypted the data off-chain.
func (s *SmartContract) StoreHealthRecord(ctx contractapi.TransactionContextInterface, recordID string, patientID string, ciphertextLocation string, patientPublicKey string) error {
	// Alg 4, Line 3: Check if caller is a Healthcare Provider
	providerMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	if providerMSPID != "Org1MSP" { // Assuming Org1 are the providers in the test network
		return fmt.Errorf("unauthorized: only healthcare providers can store health records")
	}
	providerID, _ := ctx.GetClientIdentity().GetID()

	// Alg 4, Lines 5-6: Log the metadata of the off-chain stored ciphertext
	record := HealthRecord{
		RecordID:           recordID,
		PatientID:          patientID,
		ProviderID:         providerID,
		CiphertextLocation: ciphertextLocation,
		PatientPublicKey:   patientPublicKey,
	}
	recordAsBytes, _ := json.Marshal(record)
	return ctx.GetStub().PutState(recordID, recordAsBytes)
}

// RequestDataShare allows a third party (e.g., insurance) to formally request data.
// This corresponds to the start of Algorithm 5.
func (s *SmartContract) RequestDataShare(ctx contractapi.TransactionContextInterface, requestID string, recordID string) error {
	// The function implicitly validates the requester's identity through their Fabric certificate.
	requesterID, _ := ctx.GetClientIdentity().GetID()

	// Get the patient ID from the original health record
	recordAsBytes, err := ctx.GetStub().GetState(recordID)
	if err != nil || recordAsBytes == nil {
		return fmt.Errorf("health record %s not found", recordID)
	}
	var record HealthRecord
	json.Unmarshal(recordAsBytes, &record)

	// Alg 5, Line 4: Create the sharing request on the ledger
	request := SharingRequest{
		RequestID:   requestID,
		RecordID:    recordID,
		RequesterID: requesterID,
		PatientID:   record.PatientID,
		Status:      "PENDING",
	}
	requestAsBytes, _ := json.Marshal(request)
	return ctx.GetStub().PutState(requestID, requestAsBytes)
}

// ShareDataWithConsent implements the final on-chain step of Algorithm 5.
// It is called by the Healthcare Provider AFTER getting patient consent and the re-key off-chain.
func (s *SmartContract) ShareDataWithConsent(ctx contractapi.TransactionContextInterface, eventID string, requestID string, reEncryptedCiphertextHash string) error {
	// Alg 5, Line 3: Check if caller is a Healthcare Provider
	providerMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get MSPID: %v", err)
	}
	if providerMSPID != "Org1MSP" {
		return fmt.Errorf("unauthorized: only healthcare providers can process sharing requests")
	}
	providerID, _ := ctx.GetClientIdentity().GetID()

	// Alg 5, Line 4: Get the sharing request from the ledger
	requestAsBytes, err := ctx.GetStub().GetState(requestID)
	if err != nil || requestAsBytes == nil {
		return fmt.Errorf("sharing request %s not found", requestID)
	}
	var request SharingRequest
	json.Unmarshal(requestAsBytes, &request)
	
	// Lines 7-11 of Alg 5 happen OFF-CHAIN. The provider calls this function only after they are complete.
	// This function's purpose is to log that the sharing happened.

	// Alg 5, Line 12: Log the sharing event
	event := SharingEvent{
		EventID:           eventID,
		RecordID:          request.RecordID,
		PatientID:         request.PatientID,
		RequesterID:       request.RequesterID,
		SharingProviderID: providerID,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		CiphertextHash:    reEncryptedCiphertextHash,
	}
	eventAsBytes, _ := json.Marshal(event)
	
	// Update the request status to show it has been completed
	request.Status = "APPROVED"
	requestAsBytes, _ = json.Marshal(request)
	ctx.GetStub().PutState(requestID, requestAsBytes)

	// Put the final event on the ledger
	return ctx.GetStub().PutState(eventID, eventAsBytes)
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		fmt.Printf("Error creating PRE Health chaincode: %s", err.Error())
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting PRE Health chaincode: %s", err.Error())
	}
}
