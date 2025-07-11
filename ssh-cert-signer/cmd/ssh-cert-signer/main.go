package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"
	"ssh-cert-signer/internal/handlers"
)

var caSigner ssh.Signer

func main() {
	log.Println("Starting Enclave Signing Service...")

	// Listen for connections on a VSOCK port.
	// The parent EC2 instance will connect to this listener.
	listener, err := vsock.Listen(constants.ENCLAVE_LISTENING_PORT, nil)
	if err != nil {
		log.Fatalf("FATAL: failed to listen on vsock port %d: %v", constants.ENCLAVE_LISTENING_PORT, err)
	}
	defer listener.Close()
	log.Printf("Listening on vsock port %d...", constants.ENCLAVE_LISTENING_PORT)

	// Accept and handle connections in a loop.
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ERROR: failed to accept connection: %v", err)
			continue
		}
		// Handle each connection in a new goroutine to allow concurrent processing.
		go handleConnection(conn)
	}
}

// handleConnection reads a request, signs it, and writes a response.
func handleConnection(conn net.Conn) {
	defer conn.Close()
	logging.Debug("Accepted new connection from parent instance.")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		response := processRequest(scanner.Bytes())
		sendResponse(conn, response)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("scanner.Scan() failed: %s\n", err)
	}
}

// processRequest handles a single request and returns the response
func processRequest(requestBytes []byte) messages.Response {
	logging.Debug("recv: %s", string(requestBytes))

	var req messages.Request
	if err := json.Unmarshal(requestBytes, &req); err != nil {
		return createErrorResponse(fmt.Errorf("json.Unmarshal failed: %w", err))
	}

	ctx := context.TODO()

	switch {
	case req.LoadKeySigner != nil:
		return handleLoadKeySigner(ctx, *req.LoadKeySigner)
	case req.SignSshKey != nil:
		return handleSignSshKey(ctx, *req.SignSshKey)
	default:
		return createErrorResponse(fmt.Errorf("unexpected command"))
	}
}

// handleLoadKeySigner processes a load key signer request
func handleLoadKeySigner(ctx context.Context, req messages.LoadKeySignerRequest) messages.Response {
	var err error
	caSigner, err = handlers.LoadKeySignerHandler(ctx, req)
	if err != nil {
		return createErrorResponse(err)
	}

	return messages.Response{
		LoadKeySigner: &messages.LoadKeySignerResponse{Success: true},
	}
}

// handleSignSshKey processes an SSH key signing request
func handleSignSshKey(ctx context.Context, req messages.EnclaveSigningRequest) messages.Response {
	signResponse, err := handlers.SignPublicKey(ctx, caSigner, req)
	if err != nil {
		return createErrorResponse(err)
	}

	logging.Debug("res: %v", signResponse.SignedKey)
	return messages.Response{
		SignSshKey: signResponse,
	}
}

// createErrorResponse creates a response with an error message
func createErrorResponse(err error) messages.Response {
	log.Printf("request failed: %s", err)
	errMsg := err.Error()
	return messages.Response{
		Error: &errMsg,
	}
}

// sendResponse marshals and sends a response over the connection
func sendResponse(conn net.Conn, response messages.Response) {
	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Panic(err)
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	conn.Write(responseBytes)
	conn.Write([]byte{'\n'})
}
