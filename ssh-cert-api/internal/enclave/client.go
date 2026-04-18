// Package enclave is the host-side client for the Nitro Enclave signing
// service. It dials the enclave over VSOCK, sends a JSON SignSshKey
// request, and returns the signed certificate. Authentication and
// authorization happen in the api package; this package assumes the
// caller has already decided the signing should proceed.
package enclave

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"

	"github.com/mdlayher/vsock"
)

type Signer interface {
	SignPublicKey(req *messages.EnclaveSigningRequest) (string, error)
	Close() error
}

var _ Signer = (*Client)(nil)

type Client struct {
	vsockPort int
}

func NewClient() (*Client, error) {
	return &Client{
		vsockPort: constants.ENCLAVE_LISTENING_PORT,
	}, nil
}

func (c *Client) Close() error {
	logging.Debug("Enclave client closed")
	return nil
}

// CommunicateWithEnclave sends a JSON request to the enclave and returns the response
func CommunicateWithEnclave(enclaveCID uint32, request any, response any) error {
	// Create VSOCK connection to enclave
	conn, err := vsock.Dial(enclaveCID, constants.ENCLAVE_LISTENING_PORT, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to enclave: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Set read/write timeouts
	err = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		return fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Marshal request to JSON
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	logging.Debug("Sending request to enclave: %s", redactRequest(request))
	_, err = conn.Write(append(requestBytes, '\n')) // Send request to enclave with newline delimiter
	if err != nil {
		return fmt.Errorf("failed to send request to enclave: %w", err)
	}

	reader := bufio.NewReader(conn) // Use buffered reader to read line-by-line response
	responseBytes, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("failed to read response from enclave: %w", err)
	}
	logging.Debug("Received response from enclave: %s", string(responseBytes))

	// Parse response into the provided struct
	err = json.Unmarshal(responseBytes, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return nil
}

// redactRequest returns a JSON string safe for logging, with credentials truncated.
func redactRequest(request any) string {
	r, ok := request.(messages.Request)
	if ok && r.LoadKeySigner != nil {
		r.LoadKeySigner = &messages.LoadKeySignerRequest{
			EncryptedKey: r.LoadKeySigner.EncryptedKey,
			Credentials:  r.LoadKeySigner.Credentials.Redacted(),
		}
		request = r
	}
	b, err := json.Marshal(request)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}

func (c *Client) SignPublicKey(req *messages.EnclaveSigningRequest) (string, error) {
	request := messages.Request{
		SignSshKey: req,
	}

	var response messages.Response
	err := CommunicateWithEnclave(constants.ENCLAVE_CID, request, &response)
	if err != nil {
		return "", err
	}

	// Check for error in response
	if response.Error != nil {
		return "", fmt.Errorf("enclave error: %s", *response.Error)
	}

	// Extract signed key from response
	if response.SignSshKey != nil && response.SignSshKey.SignedKey != "" {
		log.Printf("Successfully signed SSH key ID: %s", req.KeyID)
		return response.SignSshKey.SignedKey, nil
	}

	return "", fmt.Errorf("no signed key in response")
}
