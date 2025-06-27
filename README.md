# **Cerberus: An AWS Nitro Enclave SSH Certificate Authority**

Cerberus is a highly secure, automated SSH Certificate Authority (CA) built to run on AWS. It leverages AWS Nitro Enclaves to ensure that the CA's private signing key is never exposed to the host operating system, network, or any user. It provides a web API for users to request signed SSH certificates after authenticating with Kerberos.

## **Features**

* **Ultimate Key Security**: The CA private key is loaded directly into a secure Nitro Enclave and never leaves it. It is not accessible from the parent EC2 instance.  
* **Kerberos Authentication**: The public-facing API uses Kerberos (SPNEGO) to authenticate users, integrating seamlessly with existing enterprise identity systems like Active Directory or MIT Kerberos.  
* **Flexible, Group-Based Authorization**: A simple, powerful YAML file (rules.yaml) defines which users belong to which groups and what permissions each group has (e.g., certificate validity, allowed server principals).  
* **Secure Communication**: The API server communicates with the signing service in the enclave over a secure, isolated VSOCK connection, not the standard network stack.  
* **Auditable**: All issued certificates can be embedded with custom metadata, such as the requesting user's principal and a timestamp, for clear audit trails.  
* **Easy to Deploy**: Makefile automation simplifies building the application binaries and the Enclave Image File (.eif).

## **Architecture**

The system is composed of two primary services that work together to provide a secure signing workflow.

```
\+-----------+       \+---------------------------------+       \+--------------------------------------+  
|           |       |      EC2 Instance (Host OS)     |       |         AWS Nitro Enclave          |  
|   User    |--(1)--\>|                                 |--(3)--\>|                                      |  
| (Kerberos)| HTTPS |      ssh-cert-api Service       | VSOCK |       ssh-cert-signer Service        |  
|   Client  |       |                                 |       |                                      |  
|           |\<-(6)--| (Web API, Auth, Authorization)  |\<-(5)--| (Cryptographic Signing Operations)   |  
\+-----------+       \+-----------------------+---------+       \+------------------------+-------------+  
                                            |                                          |  
                                            | (2) Reads rules                          | (4) Fetches key  
                                            |                                          |  
                                     \+------v------+                            \+------v------+  
                                     | rules.yaml  |                            | AWS Param.  |  
                                     \+-------------+                            | Store (SSM) |  
                                                                                \+-------------+
```

1. A user with a valid Kerberos ticket makes an HTTPS request to the ssh-cert-api service with the public key they want signed.  
2. The ssh-cert-api service authenticates the user's Kerberos ticket and loads rules.yaml to authorize the request based on the user's group membership.  
3. If authorized, the API service forwards a detailed signing request to the ssh-cert-signer service running in the Nitro Enclave via a secure VSOCK.  
4. The ssh-cert-signer service fetches the CA private key from AWS Systems Manager (SSM) Parameter Store.  
5. The enclave service signs the certificate and returns it to the API service over the VSOCK.  
6. The ssh-cert-api service sends the signed certificate back to the user.

## **Components**

### **1\. ssh-cert-api (Web API Service)**

This is the user-facing component that runs on the parent EC2 instance.

* **Responsibilities**:  
  * Listens for HTTPS requests.  
  * Authenticates users via Kerberos/SPNEGO.  
  * Parses and validates rules.yaml.  
  * Authorizes requests against the defined rules.  
  * Acts as a client to the enclave service.  
* **Configuration**:  
  * rules.yaml: Defines user groups and permissions.  
  * **Environment Variables**:  
    * CONFIG\_PATH: Path to rules.yaml.  
    * KERBEROS\_KEYTAB\_PATH: Path to the service's keytab file for SPNEGO.  
    * ENCLAVE\_VSOCK\_PORT: The VSOCK port the enclave service is listening on (e.g., 5000).

### **2\. ssh-cert-signer (Enclave Signing Service)**

This is a minimal, secure service that runs inside the AWS Nitro Enclave.

* **Responsibilities**:  
  * Fetches the CA private key from AWS Parameter Store on startup.  
  * Listens for signing requests on a VSOCK port.  
  * Performs the cryptographic signing operation.  
  * Returns the signed certificate or an error.  
* **Configuration**:  
  * **Environment Variables**:  
    * CA\_KEY\_PARAMETER\_NAME: The name of the SecureString parameter in AWS SSM Parameter Store containing the CA private key.

## **Prerequisites**

* Go 1.18+  
* Docker  
* AWS CLI  
* [AWS Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli.html)  
* An EC2 instance with Nitro Enclaves enabled.  
* A Kerberos Key Distribution Center (KDC) and a keytab file for the API service.

## **Setup and Deployment**

### **Step 1: Prepare the CA Private Key**

1. Generate an SSH key pair to serve as your Certificate Authority. **Guard the private key carefully.**  
   ssh-keygen \-t rsa \-b 4096 \-f ca\_key \-C "Cerberus SSH CA"

2. Store the private key (ca\_key) as a SecureString in AWS SSM Parameter Store. You can do this via the AWS Console or CLI:  
   aws ssm put-parameter \\  
       \--name "/cerberus/ca-private-key" \\  
       \--value "file://ca\_key" \\  
       \--type "SecureString"

### **Step 2: Configure ssh-cert-api**

1. **Create rules.yaml**: Customize the rules.yaml file to define your user groups and their permissions.  
2. **Generate TLS Certificates**: For local testing or production, generate TLS certificates.  
   make \-C ssh-cert-api/ tls-certs

3. **Create go.mod files**:  
   cd ssh-cert-api && go mod init ssh-cert-api && go mod tidy

### **Step 3: Build the Artifacts**

1. Build the Enclave Image File (.eif):  
   Navigate to the ssh-cert-signer directory and run make. This will compile the Go binary and package it into a deployable enclave file.  
   cd ssh-cert-signer  
   go mod init ssh-cert-signer && go mod tidy  
   make eif

   This creates ssh-cert-signer.eif. Upload this file to an S3 bucket accessible by your EC2 instance.  
2. Build the API Binary:  
   Navigate to the ssh-cert-api directory and run make.  
   cd ssh-cert-api  
   make build

   This creates the binary at bin/ssh-cert-api.

### **Step 4: Run the Services on EC2**

1. **Deploy ssh-cert-api**: Copy the ssh-cert-api binary, rules.yaml, your TLS certs, and the Kerberos keytab to your EC2 instance.  
2. Run the Enclave:  
   Use nitro-cli to run your enclave. You must provide enough memory and set the CA\_KEY\_PARAMETER\_NAME environment variable.  
   nitro-cli run-enclave \\  
       \--cpu-count 2 \\  
       \--memory 512 \\  
       \--eif-path ssh-cert-signer.eif \\  
       \--enclave-cid 16 \\  
       \--debug-mode

   \# In another terminal, set the environment variable for the signer  
   export CA\_KEY\_PARAMETER\_NAME="/cerberus/ca-private-key"

3. Run the API Service:  
   Set the required environment variables and run the binary.  
   export CONFIG\_PATH="./rules.yaml"  
   export KERBEROS\_KEYTAB\_PATH="./service.keytab"  
   export ENCLAVE\_VSOCK\_PORT=5000

   ./bin/ssh-cert-api

## **Usage Example**

Once the services are running, a user can request a signed certificate using curl and kinit.

1. **Get a Kerberos Ticket**:  
   kinit alice@YOUR-REALM.COM

2. Make the API Request:  
   Use curl with the \--negotiate flag to perform SPNEGO authentication.  
   \# Create a JSON payload with your public key  
   cat \> request.json \<\<EOF  
   {  
     "ssh\_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ... alice@macbook",  
     "principals": \["root", "ubuntu"\]  
   }  
   EOF

   \# Make the authenticated request  
   curl \-X POST \\  
     \--cacert cert.pem \\  
     \-H "Content-Type: application/json" \\  
     \--negotiate \-u : \\  
     \--data @request.json \\  
     https://your-ec2-instance.com:8443/sign

3. Success Response:  
   On success, the API will return a JSON object with the signed key.  
   {  
     "signed\_key": "ssh-rsa-cert-v01@openssh.com AAA..."  
   }  
