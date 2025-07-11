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
		return fmt.Errorf("failed to connect to enclave: %v", err)
	}
	defer conn.Close()

	// Set read/write timeouts
	err = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		return fmt.Errorf("failed to set connection deadline: %v", err)
	}

	// Marshal request to JSON
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	logging.Debug("Sending request to enclave: %s", string(requestBytes))
	_, err = conn.Write(append(requestBytes, '\n')) // Send request to enclave with newline delimiter
	if err != nil {
		return fmt.Errorf("failed to send request to enclave: %v", err)
	}

	reader := bufio.NewReader(conn) // Use buffered reader to read line-by-line response
	responseBytes, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("failed to read response from enclave: %v", err)
	}
	logging.Debug("Received response from enclave: %s", string(responseBytes))

	// Parse response into the provided struct
	err = json.Unmarshal(responseBytes, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return nil
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
