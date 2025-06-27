package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"ssh-cert-api/config"
	"ssh-cert-api/pkg/api"
	"ssh-cert-api/pkg/auth"
	"ssh-cert-api/pkg/enclave"
)

func main() {
	log.Println("Starting SSH Certificate API...")

	// --- 1. Load Configuration ---
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "rules.yaml" // Default for local development
		log.Printf("CONFIG_PATH not set, using default: %s", configPath)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Println("Configuration loaded successfully.")

	// --- 2. Initialize Dependencies ---
	kerberosAuthenticator := auth.NewKerberosAuthenticator()
	enclaveClient, err := enclave.NewClient()
	if err != nil {
		log.Fatalf("Failed to initialize enclave client: %v", err)
	}
	defer enclaveClient.Close()

	// --- 3. Setup API Server ---
	server, err := api.NewServer(cfg, kerberosAuthenticator, enclaveClient)
	if err != nil {
		log.Fatalf("Failed to initialize API server: %v", err)
	}

	// --- 4. Define the HTTP server with authentication middleware ---
	httpServer := &http.Server{
		Addr:         ":8443",
		Handler:      server.Router(), // The router now includes the middleware
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// --- 5. Start Server ---
	log.Println("Server listening on https://localhost:8443")
	// For local dev, generate self-signed certs:
	// go run $(go env GOROOT)/src/crypto/tls/generate_cert.go --host localhost
	err = httpServer.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("Failed to start HTTPS server: %v. Ensure cert.pem and key.pem are present.", err)
	}
}
