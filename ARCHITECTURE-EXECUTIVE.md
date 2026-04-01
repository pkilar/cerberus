# Cerberus SSH Certificate Authority
## Executive Architecture Overview

**Document Version:** 1.0
**Last Updated:** 2025-11-11
**Target Audience:** Executives, Technical Managers, Security Leaders

---

## Executive Summary

Cerberus is a highly secure SSH Certificate Authority (CA) system designed for enterprise environments that require the highest levels of cryptographic security. Built on AWS infrastructure, it leverages AWS Nitro Enclaves—a hardware-isolated compute environment—to ensure that the organization's SSH certificate signing keys are never exposed to potential compromise, even from privileged administrators.

### Key Value Propositions

- **Maximum Security**: Private signing keys are cryptographically isolated in hardware enclaves, unreachable by any software or user
- **Enterprise Integration**: Seamless integration with existing Kerberos/Active Directory infrastructure
- **Operational Efficiency**: Automated certificate issuance eliminates manual key management overhead
- **Compliance Ready**: Built-in audit trails and access controls support regulatory requirements
- **Zero Trust Architecture**: Enforces least-privilege access with time-limited, purpose-specific credentials

### Business Impact

| Metric                   | Traditional SSH Keys             | Cerberus Solution                   |
| ------------------------ | -------------------------------- | ----------------------------------- |
| Key Compromise Risk      | High (keys persist indefinitely) | Minimal (time-limited certificates) |
| Access Revocation Time   | Hours to days                    | Reduced (short-lived certificates; removal stops future issuance) |
| Audit Trail Completeness | Partial (login logs only)        | Issuance-level (certificate signing events logged)               |
| Administrative Overhead  | High (manual key distribution)   | Low (automated issuance)            |
| Compliance Posture       | Manual controls                  | Automated policy enforcement        |

---

## Business Context

### The Problem: Traditional SSH Key Management

Organizations typically manage server access using static SSH keys that present several critical challenges:

1. **Persistent Access**: SSH keys don't expire, creating permanent backdoors if compromised
2. **No Centralized Control**: Keys are distributed across user machines with no central audit trail
3. **Difficult Revocation**: Removing access requires manually updating every server's authorized_keys file
4. **Limited Context**: No metadata about who requested access, when, or for what purpose
5. **Compliance Gaps**: Difficult to prove who had access to what resources at specific times

### The Solution: Certificate-Based Authentication

SSH certificates provide temporary, auditable credentials that solve these challenges:

- **Time-Limited**: Certificates automatically expire (e.g., after 8 hours)
- **Centralized Issuance**: All access requests flow through a single, auditable authority
- **Granular Permissions**: Certificates specify exactly which servers and accounts can be accessed
- **Built-in Context**: Certificates embed user identity, timestamp, and authorization details
- **Instant Revocation**: Access ends automatically when certificates expire

### Why Nitro Enclaves?

The Certificate Authority's private key is the "crown jewel"—if compromised, an attacker could issue valid certificates for any server. Traditional systems store this key in software, making it vulnerable to:

- Operating system vulnerabilities
- Malicious insiders with root access
- Memory extraction attacks
- Supply chain compromises

AWS Nitro Enclaves provide a **hardware-isolated compute environment** where the private key exists only in encrypted memory unreachable from the host operating system, even by AWS administrators or your own root users.

---

## Architecture Overview

### High-Level System Design

```
┌────────────────────────────────────────────────────────────────────┐
│                           User Experience                          │
│                                                                    │
│  User authenticates with Kerberos → Requests certificate →         │
│  Receives time-limited certificate → Uses it to access servers     │
└────────────────────────────────────────────────────────────────────┘
                                    ↓
┌────────────────────────────────────────────────────────────────────┐
│                         Security Layers                            │
│                                                                    │
│  Layer 1: Kerberos Authentication (Who are you?)                   │
│  Layer 2: Group Authorization (What can you do?)                   │
│  Layer 3: Certificate Signing (Cryptographic proof)                │
│  Layer 4: Hardware Isolation (Key protection)                      │
└────────────────────────────────────────────────────────────────────┘
```

### Component Architecture

Cerberus consists of two tightly integrated services that work together to provide secure certificate issuance:

```
┌──────────────────────────────────────────────────────────────────┐
│                        AWS EC2 Instance (Host)                   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │              ssh-cert-api (Public API Service)            │   │
│  │                                                           │   │
│  │  • HTTPS endpoint for certificate requests                │   │
│  │  • Kerberos/SPNEGO authentication                         │   │
│  │  • Group-based authorization                              │   │
│  │  • Request validation and routing                         │   │
│  │  • Audit logging                                          │   │
│  └────────────────┬──────────────────────────────────────────┘   │
│                   │                                              │
│                   │ Secure VSOCK Connection                      │
│                   │ (Not exposed to network)                     │
│                   ↓                                              │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                 AWS Nitro Enclave (Isolated)              │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────┐      │   │
│  │  │   ssh-cert-signer (Signing Service)             │      │   │
│  │  │                                                 │      │   │
│  │  │  • Loads KMS-encrypted CA private key           │      │   │
│  │  │  • Performs cryptographic signing               │      │   │
│  │  │  • Returns signed certificates                  │      │   │
│  │  │  • Key NEVER leaves this environment            │      │   │
│  │  └─────────────────────────────────────────────────┘      │   │
│  │                                                           │   │
│  │     Hardware-Isolated Compute Environment                 │   │
│  │     • No network access                                   │   │
│  │     • No persistent storage                               │   │
│  │     • Cryptographically attested                          │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
                            ↓
                    ┌───────────────┐
                    │   AWS KMS     │
                    │               │
                    │ Key encryption│
                    │ and decryption│
                    └───────────────┘
```

---

## Detailed Component Analysis

### 1. API Service (ssh-cert-api)

**Location**: Runs on the EC2 instance host operating system
**Purpose**: Public-facing gateway for certificate requests
**Technology**: Go-based HTTPS web service

#### Responsibilities

1. **Authentication**: Validates Kerberos tickets using SPNEGO protocol
2. **Authorization**: Determines if the authenticated user is permitted to request specific access
3. **Request Validation**: Ensures certificate requests conform to security policies
4. **Enclave Communication**: Forwards authorized requests to the signing service
5. **Response Handling**: Returns signed certificates or error messages to users
6. **Audit Logging**: Records all authentication and authorization decisions

#### Security Characteristics

- Uses TLS/HTTPS for all external communication
- Does not have access to the CA private key
- Cannot sign certificates independently
- Enforces least-privilege access controls
- Logs all access attempts for compliance

#### Configuration

The API service uses a YAML configuration file (`config.yaml`) that defines:

- **User Groups**: Collections of Kerberos principals (e.g., "backend-engineers", "data-analysts")
- **Certificate Rules**: Policies for each group including:
  - Maximum validity period (e.g., 8 hours)
  - Allowed server accounts (principals)
  - SSH permissions (port forwarding, PTY allocation, etc.)
  - Network restrictions (source IP addresses)
  - Custom metadata for audit trails

**Example Policy**:
```yaml
groups:
  backend-engineers:
    members:
      - "alice@COMPANY.COM"
      - "bob@COMPANY.COM"
    certificate_rules:
      validity: "8h"
      allowed_principals:
        - "root"
        - "ec2-user"
      permissions:
        permit-pty: ""
        permit-port-forwarding: ""
      critical_options:
        source-address: "10.0.0.0/8"  # Only from corporate network
```

### 2. Signing Service (ssh-cert-signer)

**Location**: Runs inside AWS Nitro Enclave
**Purpose**: Cryptographic signing operations
**Technology**: Minimal Go service with no network access

#### Responsibilities

1. **Key Management**: Loads and decrypts the CA private key from AWS KMS
2. **Cryptographic Signing**: Generates SSH certificates using the CA key
3. **Request Processing**: Handles signing requests from the API service via VSOCK
4. **Response Generation**: Returns signed certificates or error messages

#### Security Characteristics

- **Hardware Isolation**: Cannot be accessed from the host operating system
- **No Network Access**: Communicates only via VSOCK (virtual socket)
- **No Persistent Storage**: Key exists only in encrypted memory
- **Minimal Attack Surface**: Runs only essential signing code
- **Cryptographic Attestation**: Can prove its identity and configuration to AWS KMS

#### Key Protection Mechanism

The CA private key protection follows a multi-layer approach:

1. **At Rest**: Key is encrypted with AWS KMS and stored on disk
2. **In Transit**: Key is decrypted by AWS KMS and sent over encrypted channel
3. **In Use**: Key exists only in enclave memory, unreachable from host OS
4. **Lifecycle**: Key never exists in plaintext outside the enclave

### 3. Communication Protocol

The API and Signing services communicate over **VSOCK** (Virtual Socket), a secure communication channel that:

- Does not traverse the network stack
- Cannot be intercepted by network monitoring tools
- Is accessible only to host processes that explicitly open the VSOCK socket (not exposed on the IP network)
- Provides point-to-point communication between host and enclave

**Request Flow**:
1. API service creates a `SigningRequest` message with certificate parameters
2. Message is sent over VSOCK to the enclave
3. Signing service validates the request
4. Signing service signs the certificate with the CA private key
5. Signed certificate is returned over VSOCK
6. API service returns the certificate to the user

---

## Security Architecture

### Defense in Depth Strategy

Cerberus implements multiple layers of security controls:

#### Layer 1: Authentication (Identity Verification)

- **Mechanism**: Kerberos/SPNEGO authentication
- **Integration**: Works with Active Directory, MIT Kerberos, or any Kerberos KDC
- **Protection**: Prevents unauthorized users from making requests
- **Standard**: Industry-standard enterprise authentication protocol

#### Layer 2: Authorization (Access Control)

- **Mechanism**: Group-based policy enforcement
- **Granularity**: Specific principals, permissions, and network restrictions per group
- **Flexibility**: Policies defined in human-readable YAML configuration
- **Principle**: Least-privilege access (users get minimum necessary permissions)

#### Layer 3: Cryptographic Isolation (Key Protection)

- **Mechanism**: AWS Nitro Enclaves hardware isolation
- **Protection**: Private key unreachable by any software or administrator
- **Attestation**: Enclave can prove its identity and integrity to AWS services
- **Standard**: FIPS 140-2 Level 2 equivalent protection

#### Layer 4: Time-Based Expiration (Limited Exposure)

- **Mechanism**: Short-lived certificates (configurable, typically 1-8 hours)
- **Benefit**: Even if a certificate is stolen, it expires quickly
- **Comparison**: Traditional SSH keys persist indefinitely

#### Layer 5: Audit and Monitoring (Visibility)

- **Mechanism**: Comprehensive logging of all issuance and usage
- **Content**: Who requested access, when, for which servers, and with what permissions
- **Integration**: Logs can be forwarded to SIEM systems for analysis

### Threat Model and Mitigations

| Threat                    | Traditional SSH                             | Cerberus Mitigation                      |
| ------------------------- | ------------------------------------------- | ---------------------------------------- |
| Stolen SSH key            | Key works forever                           | Certificates expire automatically        |
| Compromised administrator | Can steal CA key from filesystem            | CA key unreachable, even from root       |
| Malicious insider         | Can copy keys to unauthorized systems       | All requests authenticated and logged    |
| Lateral movement          | Attacker uses stolen key across environment | Certificates limited to specific servers |
| No audit trail            | Can't prove who accessed what               | Complete certificate issuance log        |
| Persistent backdoors      | Keys remain after employee leaves           | Certificates expire, no manual cleanup   |

### Compliance and Governance

Cerberus supports regulatory and compliance requirements through:

1. **Access Controls**: Enforces separation of duties (authentication ≠ authorization ≠ signing)
2. **Audit Trails**: Complete records of certificate issuance and approval
3. **Time Limitations**: Ensures access is reviewed and re-authorized regularly
4. **Key Protection**: Meets or exceeds cryptographic key storage standards
5. **Policy Enforcement**: Automated controls reduce human error

**Relevant Standards**:
- SOC 2 Type II (Access Control, Logging, Key Management)
- PCI DSS 3.2.1 (Requirement 8: Unique ID, Requirement 10: Logging)
- NIST 800-53 (IA-2: Identification and Authentication, AU-2: Audit Events)
- HIPAA Security Rule (164.312: Access Control, Audit Controls)

---

## Operational Model

### Day-to-Day Usage

#### For End Users (Engineers)

1. **Obtain Kerberos Ticket**: `kinit alice@COMPANY.COM` (already part of daily workflow)
2. **Request Certificate**: Send HTTPS request with public key and desired principals
3. **Receive Certificate**: Get time-limited certificate in response (typically < 1 second)
4. **Use Certificate**: SSH to servers using the signed certificate
5. **Certificate Expires**: After validity period (e.g., 8 hours), request a new one

**User Experience**: Transparent—users authenticate once with Kerberos, then request certificates as needed. Can be scripted or integrated into existing workflows.

#### For Administrators

1. **Define Groups**: Create logical groups in `config.yaml` (e.g., "database-admins", "app-developers")
2. **Assign Users**: Add Kerberos principals to appropriate groups
3. **Set Policies**: Define validity periods, allowed principals, and permissions per group
4. **Monitor Usage**: Review audit logs for anomalies or policy violations
5. **Update Policies**: Modify `config.yaml` as organizational needs change

**Administrative Overhead**: Minimal after initial setup. No key distribution, no server-by-server configuration updates, no manual access revocation.

### Certificate Lifecycle

```
┌─────────────┐
│   Request   │  User authenticates and requests certificate
└──────┬──────┘
       ↓
┌─────────────┐
│  Validation │  API validates identity and authorization
└──────┬──────┘
       ↓
┌─────────────┐
│   Signing   │  Enclave signs certificate with CA key
└──────┬──────┘
       ↓
┌─────────────┐
│   Issuance  │  Certificate returned to user
└──────┬──────┘
       ↓
┌─────────────┐
│    Usage    │  User accesses servers with certificate
└──────┬──────┘
       ↓
┌─────────────┐
│  Expiration │  Certificate becomes invalid (automatic)
└─────────────┘
```

**Timeline**: Entire request-to-issuance process completes in < 1 second. Certificate validity is configurable per group (typically 1-8 hours).

### Disaster Recovery and Business Continuity

#### CA Key Backup

- **Primary Storage**: KMS-encrypted key stored on EC2 instance
- **Backup Strategy**: KMS-encrypted key can be stored in S3 or backed up offline
- **Recovery**: Copy encrypted key to new EC2 instance and restart services

#### Service Availability

- **Single Point of Failure**: The enclave instance is critical infrastructure
- **Mitigation Options**:
  - Multi-region deployment with separate CA keys
  - Active-passive failover with shared CA key
  - Load balancing across multiple API instances
- **Recovery Time Objective (RTO)**: < 15 minutes with proper automation
- **Recovery Point Objective (RPO)**: Zero (no data loss, stateless service)

#### Key Rotation

- **Current Limitation**: Requires manual rotation by generating new CA key pair
- **Process**:
  1. Generate new CA key pair
  2. Encrypt with KMS and deploy to enclave
  3. Distribute new public key to all SSH servers
  4. Phase out old CA key over transition period
- **Recommended Frequency**: Annually or as required by policy

---

## Use Cases and Benefits

### Use Case 1: Production Server Access

**Scenario**: Engineers need to access production servers for troubleshooting and maintenance.

**Traditional Approach**:
- Engineers have long-lived SSH keys on their laptops
- Keys are added to `authorized_keys` on each server
- Keys persist indefinitely, creating security risk
- When engineer leaves, keys must be manually removed from all servers

**Cerberus Approach**:
- Engineer requests certificate valid for 8 hours
- Certificate grants access only to production servers
- Certificate includes engineer's identity for audit
- Certificate expires automatically, no cleanup needed
- When engineer leaves, change takes effect within 8 hours maximum

**Benefits**: Reduced risk, better audit trail, automatic access revocation

### Use Case 2: Third-Party Contractor Access

**Scenario**: External contractor needs temporary access to staging environment.

**Traditional Approach**:
- Create SSH key for contractor
- Add key to staging servers
- Remember to remove key when contract ends
- Risk: Key may not be removed, creating persistent backdoor

**Cerberus Approach**:
- Create temporary group for contractor with 24-hour validity limit
- Add contractor's Kerberos principal to group
- Certificate limited to staging servers only
- When contract ends, remove from group—access ends immediately

**Benefits**: Time-limited access, reduced operational overhead, instant revocation

### Use Case 3: Break-Glass Emergency Access

**Scenario**: Critical incident requires immediate production access outside normal hours.

**Traditional Approach**:
- Shared "emergency" SSH key with broad permissions
- Multiple people know the key
- No way to identify who used it
- Key remains valid after emergency

**Cerberus Approach**:
- Create "incident-response" group with elevated permissions
- Temporarily add on-call engineers to group
- All access logged with engineer identity
- Certificates expire after 2 hours
- Remove engineers from group after incident

**Benefits**: Individual accountability, automatic expiration, complete audit trail

### Use Case 4: Compliance and Auditing

**Scenario**: Organization must demonstrate access controls for SOC 2 audit.

**Traditional Approach**:
- Collect SSH keys from servers
- Try to correlate keys with users (often impossible)
- Demonstrate key removal processes (manual, error-prone)
- Show server login logs (doesn't prove authorization)

**Cerberus Approach**:
- Show certificate issuance logs with user identity, timestamp, and permissions
- Demonstrate automated policy enforcement in `config.yaml`
- Prove short-lived credentials (time-limited access)
- Show complete audit trail from request to usage

**Benefits**: Simplified compliance, reduced audit scope, demonstrable controls

---

## Technical Requirements

### Infrastructure Requirements

1. **AWS Account**: With permissions for EC2, KMS, and IAM
2. **EC2 Instance**: With Nitro Enclaves enabled
   - Recommended: m5.xlarge or c5.xlarge (minimum 2 vCPUs, 4GB RAM)
   - Architecture: AMD64 or ARM64
3. **AWS KMS**: For encrypting/decrypting the CA private key
4. **Network**: Outbound HTTPS access to AWS KMS

### Software Requirements

1. **Operating System**: Amazon Linux 2023, Ubuntu 20.04+, or RHEL 8+
2. **Nitro Enclaves CLI**: Provided by AWS
3. **Kerberos Infrastructure**: Active Directory or MIT Kerberos KDC
4. **DNS**: For hostname resolution

### Personnel Requirements

1. **Initial Setup**: Cloud engineer familiar with AWS (1-2 days)
2. **Configuration**: Security engineer to define access policies (4-8 hours)
3. **Operations**: System administrator for ongoing monitoring (1-2 hours/week)

### Cost Estimate

| Component                | Monthly Cost (Estimated)   |
| ------------------------ | -------------------------- |
| EC2 Instance (m5.xlarge) | ~$140                      |
| KMS Key                  | $1 + $0.03/10,000 requests |
| Data Transfer            | Minimal (< $5)             |
| **Total**                | **~$150/month**            |

**Note**: Costs are approximate and vary by region and usage patterns.

---

## Risk Assessment

### Technical Risks

| Risk                               | Likelihood | Impact | Mitigation                                              |
| ---------------------------------- | ---------- | ------ | ------------------------------------------------------- |
| Enclave service failure            | Medium     | High   | Automated health checks, quick restart procedures       |
| KMS unavailability                 | Low        | High   | Enclave keeps key in memory, KMS only needed at startup |
| Configuration errors               | Medium     | Medium | Schema validation, testing in staging environment       |
| Certificate expiration mid-session | High       | Low    | Longer validity periods for critical operations         |

### Operational Risks

| Risk                             | Likelihood | Impact   | Mitigation                                                   |
| -------------------------------- | ---------- | -------- | ------------------------------------------------------------ |
| Policy misconfiguration          | Medium     | Medium   | Peer review of config changes, audit logging                 |
| Lost/stolen user credentials     | Medium     | Medium   | Short-lived certificates limit exposure window               |
| Insider threat                   | Low        | High     | Complete audit trail, multi-person authorization for changes |
| Enclave compromise (theoretical) | Very Low   | Critical | Hardware-level isolation makes this extremely difficult      |

### Business Risks

| Risk                     | Likelihood | Impact | Mitigation                                                |
| ------------------------ | ---------- | ------ | --------------------------------------------------------- |
| User adoption resistance | Medium     | Medium | Training, documentation, gradual rollout                  |
| Service downtime         | Low        | High   | HA architecture, monitoring, incident response procedures |
| Regulatory changes       | Low        | Medium | Flexible policy engine, comprehensive logging             |

---

## Implementation Roadmap

### Phase 1: Proof of Concept (2-4 weeks)

**Objectives**:
- Deploy Cerberus in non-production environment
- Configure test groups and policies
- Validate integration with Kerberos
- Train initial administrator team

**Deliverables**:
- Functional Cerberus instance
- Test configuration
- Documentation
- Training materials

### Phase 2: Pilot Program (4-8 weeks)

**Objectives**:
- Roll out to limited user group (e.g., one team)
- Monitor usage and collect feedback
- Refine policies based on real usage
- Develop operational procedures

**Deliverables**:
- Production-grade configuration
- Operational runbooks
- User documentation
- Success metrics

### Phase 3: Production Deployment (8-12 weeks)

**Objectives**:
- Deploy to production environment
- Gradually migrate user groups from SSH keys
- Implement monitoring and alerting
- Establish support procedures

**Deliverables**:
- Full production deployment
- Monitoring dashboards
- Support documentation
- Migration plan completion

### Phase 4: Optimization (Ongoing)

**Objectives**:
- Fine-tune policies based on usage patterns
- Implement high availability if needed
- Automate certificate renewal workflows
- Regular security reviews

**Deliverables**:
- Optimized configuration
- Automation scripts
- Security assessment reports
- Continuous improvement plan

---

## Recommendations

### Immediate Actions

1. **Evaluate Current Risk**: Assess exposure from long-lived SSH keys in your environment
2. **Identify Pilot Users**: Select a team willing to test the new approach
3. **Review Compliance Requirements**: Determine if Cerberus helps meet regulatory obligations
4. **Budget Approval**: Secure funding for POC deployment (~$500 for 3-month trial)

### Strategic Considerations

1. **Zero Trust Journey**: Cerberus is a component of a broader zero trust architecture
2. **Secret Management**: Consider similar approaches for other credentials (databases, APIs)
3. **Automation Opportunity**: Certificate issuance can be integrated into CI/CD pipelines
4. **Cloud-Native Security**: Leveraging cloud security primitives (KMS, Nitro) reduces operational burden

### Success Metrics

Track these metrics to measure Cerberus effectiveness:

| Metric                    | Baseline (SSH Keys)  | Target (Cerberus)           |
| ------------------------- | -------------------- | --------------------------- |
| Average key lifetime      | Indefinite           | 8 hours                     |
| Access revocation time    | Days                 | Hours (certificate expiry)  |
| Audit completeness        | Partial (login logs) | Complete (issuance + usage) |
| Security incidents        | Baseline             | Reduction expected          |
| Administrative hours/week | Baseline             | 50% reduction               |

---

## Conclusion

Cerberus represents a modern, secure approach to SSH access management that addresses the fundamental weaknesses of traditional SSH keys. By leveraging AWS Nitro Enclaves for hardware-level key protection, integrating with existing Kerberos infrastructure, and enforcing time-limited credentials, Cerberus significantly improves security posture while reducing operational overhead.

The system is particularly well-suited for organizations that:
- Handle sensitive data requiring strict access controls
- Need to demonstrate compliance with security standards
- Want to adopt zero trust security principles
- Operate in AWS cloud environments
- Have existing Kerberos/Active Directory infrastructure

### Key Takeaways

1. **Maximum Security**: Hardware isolation ensures CA key cannot be compromised
2. **Operational Efficiency**: Automated issuance eliminates manual key management
3. **Compliance Ready**: Complete audit trails and policy enforcement
4. **Enterprise Integration**: Works with existing Kerberos infrastructure
5. **Proven Technology**: Built on AWS Nitro Enclaves and standard SSH certificates

### Next Steps

1. Schedule technical deep-dive with engineering team
2. Conduct security assessment of current SSH key usage
3. Approve POC deployment budget
4. Identify pilot team and use cases
5. Begin implementation planning

---

## Appendix: Glossary

**AWS Nitro Enclaves**: Hardware-isolated compute environments that provide cryptographic attestation and secure key handling. Part of AWS Nitro System.

**Certificate Authority (CA)**: A trusted entity that signs digital certificates to verify identity. In this context, signs SSH certificates to authenticate users to servers.

**Kerberos**: A network authentication protocol that uses tickets to allow nodes to prove their identity. Commonly used with Active Directory.

**KMS (Key Management Service)**: AWS service for creating and controlling encryption keys.

**Principal**: In SSH context, a username on a server. In Kerberos context, a unique identity (e.g., alice@COMPANY.COM).

**SPNEGO**: Authentication mechanism that allows clients and servers to negotiate authentication protocols (commonly used for web-based Kerberos authentication).

**SSH Certificate**: A public key signed by a Certificate Authority that can authenticate to SSH servers. Unlike SSH keys, certificates are time-limited and contain additional metadata.

**VSOCK**: Virtual socket communication channel between host and enclave, not accessible via network.

---

## Appendix: Additional Resources

- **AWS Nitro Enclaves Documentation**: https://docs.aws.amazon.com/enclaves/
- **OpenSSH Certificate Authentication**: https://www.ssh.com/academy/ssh/certificate
- **NIST Zero Trust Architecture**: https://www.nist.gov/publications/zero-trust-architecture-sp-800-207
- **Kerberos Protocol**: https://web.mit.edu/kerberos/

---

**For questions or additional information, please contact:**
- **Technical Lead**: [Your Name/Team]
- **Security Team**: [Security Contact]
- **Project Repository**: [GitHub URL]
