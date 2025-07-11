![Cerberus](https://github.com/pkilar/cerberus/blob/master/cerberus.png?raw=true)

# **Cerberus: An AWS Nitro Enclave SSH Certificate Authority**

Cerberus is a highly secure, automated SSH Certificate Authority (CA) built to run on AWS. It leverages AWS Nitro Enclaves to ensure that the CA's private signing key is never exposed to the host operating system, network, or any user. It provides a web API for users to request signed SSH certificates after authenticating with Kerberos.

## **Features**

- **Ultimate Key Security**: The CA private key is loaded directly into a secure Nitro Enclave and never leaves it. It is not accessible from the parent EC2 instance.
- **Kerberos Authentication**: The public-facing API uses Kerberos (SPNEGO) to authenticate users, integrating seamlessly with existing enterprise identity systems like Active Directory or MIT Kerberos.
- **Flexible, Group-Based Authorization**: A simple, powerful YAML file (config.yaml) defines which users belong to which groups and what permissions each group has (e.g., certificate validity, allowed server principals).
- **Secure Communication**: The API server communicates with the signing service in the enclave over a secure, isolated VSOCK connection, not the standard network stack.
- **Auditable**: All issued certificates can be embedded with custom metadata, such as the requesting user's principal and a timestamp, for clear audit trails.
- **Easy to Deploy**: Makefile automation simplifies building the application binaries and the Enclave Image File (.eif).

## **Architecture**

The system is composed of two primary services that work together to provide a secure signing workflow.

```
+-----------+       +---------------------------------+       +--------------------------------------+
|           |       |      EC2 Instance (Host OS)     |       |         AWS Nitro Enclave            |
|   User    |--(1)->|                                 |--(3)--|                                      |
| (Kerberos)| HTTPS |      ssh-cert-api Service       | VSOCK |       ssh-cert-signer Service        |
|   Client  |       |                                 |       |                                      |
|           |<-(6)--| (Web API, Auth, Authorization)  |<-(5)--| (Cryptographic Signing Operations)   |
+-----------+       +-----------------------+---------+       +------------------------+-------------+
                                            |                                          |
                                            | (2) Reads rules                          | (4) Decrypts key
                                            |                                          |
                                     +------v------+                          +--------v-------+
                                     | config.yaml  |                         | KMS-encrypted  |
                                     +-------------+                          | CA certificate |
                                                                              +----------------+
```

1. A user with a valid Kerberos ticket makes an HTTPS request to the ssh-cert-api service with the public key they want signed.
2. The ssh-cert-api service authenticates the user's Kerberos ticket and loads config.yaml to authorize the request based on the user's group membership.
3. If authorized, the API service forwards a detailed signing request to the ssh-cert-signer service running in the Nitro Enclave via a secure VSOCK.
4. The ssh-cert-signer service fetches the CA private key from AWS KMS-encrypted storage.
5. The enclave service signs the certificate and returns it to the API service over the VSOCK.
6. The ssh-cert-api service sends the signed certificate back to the user.

## **Project Structure**

```
cerberus/
├── constants/                    # Shared constants
├── logging/                      # Logging component
├── messages/                     # Shared message types
├── ssh-cert-api/                 # API service
│   ├── cmd/ssh-cert-api/         # Main entry point
│   ├── internal/                 # Private application code
│   │   ├── api/                  # HTTP server and handlers
│   │   ├── auth/                 # Kerberos authentication
│   │   ├── config/               # Configuration management
│   │   ├── enclave/              # Enclave communication
│   │   └── proxy/                # VSOCK proxy
│   └── configs/                  # Configuration files
└── ssh-cert-signer/              # Enclave service
    ├── cmd/ssh-cert-signer/      # Main entry point
    └── internal/                 # Private application code
        ├── handlers/             # Request handlers
        └── server/               # VSOCK server
```

## **Components**

### **1. ssh-cert-api (Web API Service)**

This is the user-facing component that runs on the parent EC2 instance.

- **Responsibilities**:
  - Listens for HTTPS requests
  - Authenticates users via Kerberos/SPNEGO
  - Parses and validates configuration
  - Authorizes requests against defined rules
  - Communicates with the enclave service
- **Configuration**:
  - `configs/config.yaml`: Defines user groups and permissions
  - **Environment Variables**:
    - `CONFIG_PATH`: Path to config.yaml (default: `configs/config.yaml`)
    - `KERBEROS_KEYTAB_PATH`: Path to the service's keytab file
    - `AWS_REGION`: AWS region for KMS operations

### **2. ssh-cert-signer (Enclave Signing Service)**

This is a minimal, secure service that runs inside the AWS Nitro Enclave.

- **Responsibilities**:
  - Loads the CA private key from KMS-encrypted storage
  - Listens for signing requests on a VSOCK port
  - Performs cryptographic signing operations
  - Returns signed certificates or errors
- **Configuration**:
  - **Environment Variables**:
    - `CA_KEY_FILE_PATH`: Path to the encrypted CA key file (default: `/app/ca_key.enc`)
    - `AWS_REGION`: AWS region for KMS operations (default: `us-east-1`)

## **Prerequisites**

- Go 1.23+
- Docker
- AWS CLI
- [AWS Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli.html)
- An EC2 instance with Nitro Enclaves enabled
- A Kerberos Key Distribution Center (KDC) and a keytab file for the API service

## **Setup and Deployment**

### **Step 1: Prepare the CA Private Key**

1. **Generate an SSH key pair** to serve as your Certificate Authority:

   ```bash
   ssh-keygen -t rsa -b 4096 -f ca_key -C "Cerberus SSH CA"
   ```

2. **Encrypt the private key with KMS**:
   ```bash
   aws kms encrypt \
     --key-id "arn:aws:kms:region:account:key/key-id" \
     --plaintext fileb://ca_key \
     --output text \
     --query CiphertextBlob | base64 -d > ca_key.enc

   # Remove the unencrypted private key
   rm ca_key
   ```

3. **Copy the encrypted key to the enclave directory**:
   ```bash
   cp ca_key.enc ssh-cert-signer/
   ```

   Note: The enclave service will load the encrypted CA private key from the file path specified by `CA_KEY_FILE_PATH` environment variable (defaults to `/app/ca_key.enc`).

### **Step 2: Configure ssh-cert-api**

1. **Create configuration file**:

   ```bash
   cp ssh-cert-api/configs/config-example.yaml ssh-cert-api/configs/config.yaml
   # Edit config.yaml to define your user groups and permissions
   ```

2. **Generate TLS certificates** for HTTPS:
   ```bash
   make -C ssh-cert-api tls-certs
   ```

### **Step 3: Build the Services**

1. **Build everything**:

   ```bash
   make build  # Builds both services
   ```

2. **Build individual components**:

   ```bash
   # Build API service
   make -C ssh-cert-api build

   # Build enclave service and create EIF
   make -C ssh-cert-signer build
   make -C ssh-cert-signer eif
   ```

### **Step 4: Deploy and Run**

1. **Run the enclave**:

   ```bash
   # Start the enclave (with debug mode for development)
   make run-enclave-debug

   # Or manually with nitro-cli
   nitro-cli run-enclave \
     --cpu-count 1 \
     --memory 1024 \
     --eif-path ssh-cert-signer/ssh-cert-signer-amd64.eif \
     --enclave-cid 16 \
     --debug-mode \
     --attach-console
   ```

   Note: The enclave will automatically load the encrypted CA key from `/app/ca_key.enc` (or the path specified by `CA_KEY_FILE_PATH`) and decrypt it using KMS.

2. **Run the API service**:

   ```bash
   # Set environment variables
   export CONFIG_PATH="ssh-cert-api/configs/config.yaml"
   export KERBEROS_KEYTAB_PATH="/path/to/service.keytab"
   export AWS_REGION="us-east-1"
   export ENCLAVE_VSOCK_PORT=5000

   # Run the API service
   ./ssh-cert-api/ssh-cert-api.amd64

   # Or use the Makefile target for local development
   make run-api
   ```

## **Development and Testing**

### **Running Tests**

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific test components using test_runner.sh
./test_runner.sh api      # Run API service tests
./test_runner.sh signer   # Run signer service tests
./test_runner.sh integration  # Run integration tests
./test_runner.sh security     # Run security analysis
./test_runner.sh coverage     # Generate coverage reports
./test_runner.sh lint         # Run linting

# Run specific service tests directly
make -C ssh-cert-api test
make -C ssh-cert-signer test
```

### **Local Development**

```bash
# Run API service locally (generates TLS certs automatically)
make -C ssh-cert-api run
```

## **Usage Example**

Once the services are running, users can request signed certificates:

1. **Get a Kerberos ticket**:

   ```bash
   kinit alice@YOUR-REALM.COM
   ```

2. **Request a certificate**:

   ```bash
   # Create request payload
   cat > request.json <<EOF
   {
     "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ... alice@macbook",
     "principals": ["root", "ubuntu"]
   }
   EOF

   # Make authenticated request
   curl -X POST \
     --cacert ssh-cert-api/cert.pem \
     -H "Content-Type: application/json" \
     --negotiate -u : \
     --data @request.json \
     https://your-ec2-instance.com:8443/sign
   ```

3. **Success response**:
   ```json
   {
     "signed_key": "ssh-rsa-cert-v01@openssh.com AAA..."
   }
   ```

## **Configuration Reference**

See `ssh-cert-api/configs/config-example.yaml` for a complete configuration example with:

- User group definitions
- Certificate validity periods
- Allowed principals
- Permissions and custom attributes

## **Security Considerations**

- The CA private key never leaves the Nitro Enclave
- All communication between services uses secure VSOCK
- Kerberos provides strong authentication
- AWS KMS encrypts the CA key at rest
- Certificate signing operations are logged for audit trails

## **Troubleshooting**

- Check service logs for detailed error messages
- Verify Nitro Enclave is properly configured and running
- Ensure AWS credentials and KMS permissions are correct
- Validate Kerberos configuration and keytab file
- Use debug mode for enclave development and testing
