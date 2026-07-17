# Security Findings and Fixes

## 1. Recon: full route map

**Description:** 
The public OpenAPI document (`/openapi.json` and `/docs`) lists every route, method, and schema. This provides free reconnaissance for an attacker before they touch anything.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Internal API structure and configuration should not be publicly accessible (No information leakage).
2. **Attacker Role:** Unauthenticated External Attacker.
3. **Migration Status:** Newly exposed. Moving to Modal put the previously internal `localhost` docs on the public internet.

**The Fix:**
Disable `/docs` and `/openapi.json` in production by updating the FastAPI initialization, and put the whole gateway behind authentication.

```python
# In your main FastAPI initialization file (e.g., glc/main.py):
import os

is_prod = os.getenv("MODAL_IMAGE_ID") is not None

app = FastAPI(
    title="GLC v1 — Gateway for LLMs and Channels",
    lifespan=lifespan,
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
    dependencies=[Depends(_require_token)],
)
```

**How to Test the Fix:**
1. **Local Development:** Ran `python3 -m glc.main` and requested `/docs` and `/openapi.json`. Verified that both returned `200 OK` since `MODAL_IMAGE_ID` is missing.
2. **Production Deployment:** Ran `modal deploy modal_app.py` and requested `/openapi.json`. Verified that it returned `{"detail": "Not Found"}` because the conditional check successfully disabled the endpoint on Modal.
3. **Global Authentication:** Verified that hitting any endpoint (like `/`) without the `Authorization: Bearer <token>` header now properly restricts access.

## 2. Config disclosure (/v1/status, /v1/providers)

**Description:** 
The gateway has several "read" endpoints (`/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/routers`, `/v1/embedders`, `/v1/cost/by_agent`, `/v1/calls`) designed to show the internal health, limits, and configuration of the system. These endpoints return sensitive information such as the AI providers used, exact models, fallback routing orders, and rate limits (RPM/RPD). Because these endpoints are unauthenticated, an attacker can read your entire backend infrastructure setup.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Administrative/internal configuration endpoints must require authentication (No information leakage).
2. **Attacker Role:** Unauthenticated External Attacker.
3. **Migration Status:** Newly exposed. Moving to Modal put the previously safe `localhost` endpoints on the public internet.

**The Fix:**
Require the install token on every read endpoint that exposes internal configuration by adding `dependencies=[Depends(_require_token)]` to each specific route decorator in `glc/routes/chat.py`.

```python
# In glc/routes/chat.py, add the dependency to all config read endpoints:
from fastapi import Depends
from glc.routes.control import _require_token

@router.get("/v1/status", dependencies=[Depends(_require_token)])
async def status(request: Request):
    ...
```

**How to Test the Fix:**
1. **Unauthenticated Test:** Run `curl -s "<your-modal-url>/v1/status"`. It should now return a `401 Unauthorized` or `422 Unprocessable Entity` error because the token is missing.
2. **Authenticated Test:** Run `curl -s -H "Authorization: Bearer <your_install_token>" "<your-modal-url>/v1/status"`. It should successfully return the JSON configuration data.

## 3. Unauthenticated LLM abuse (/v1/chat)

**Description:** 
The data plane endpoints (`/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`) perform the heavy lifting of calling the LLMs. Because they are completely unauthenticated when exposed to the internet via Modal, anyone who finds the URL can drive the LLM pipeline, exhausting the rate limits, generating garbage logs, and racking up bills on the upstream AI providers.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Only authorized entities may consume resources (Data plane requires caller credentials).
2. **Attacker Role:** Unauthenticated External Attacker.
3. **Migration Status:** Newly exposed. On `localhost` this was implicitly safe, but the migration put it on the public internet with no front door.

**The Fix:**
Require a caller credential (the install token) on the data plane by adding `dependencies=[Depends(_require_token)]` to the specific execution route decorators (`/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`) in `glc/routes/chat.py`.

```python
# In glc/routes/chat.py, add the dependency to all execution endpoints:
@router.post("/v1/chat", dependencies=[Depends(_require_token)])
async def chat(req: ChatRequest, request: Request):
    ...
```

**How to Test the Fix:**
1. **Unauthenticated Test:** Run `curl -s -X POST "<your-modal-url>/v1/chat" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}'`. It will now return `401 Unauthorized` instead of trying to hit the provider.
2. **Authenticated Test:** Run the same `curl` but add the `-H "Authorization: Bearer <your_install_token>"` header to successfully execute the chat.

## 4. SSRF via image URL resolver

**Description:** 
When the gateway receives a chat request containing an image URL, it attempts to fetch the image, convert it to base64, and embed it for the LLM. Because there is no allowlist or restriction on the URL, an attacker can provide an internal address (like `127.0.0.1` or `169.254.169.254` for AWS metadata). The gateway will fetch this internal resource and process it, turning the gateway into an open proxy (Server-Side Request Forgery).

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Gateway must not bridge external requests to the internal network (No SSRF / Data plane isolation).
2. **Attacker Role:** External Attacker.
3. **Migration Status:** Newly exposed. Running on Modal placed the gateway into a cloud network where internal metadata and adjacent cloud services are reachable.

**The Fix:**
Rewrite the image resolver in `glc/routes/chat.py` to intercept the URL fetching process. Instead of automatically following redirects, we manually resolve the DNS of the hostname, check if the IP is private/loopback/link-local using Python's `ipaddress` module, and repeat this check for every single redirect.

```python
# In glc/routes/chat.py, update _fetch_to_data_url:
async def _check_url(u: str):
    parsed = urlparse(u)
    # Perform DNS resolution and check against loopback/private ranges
    ...
```

**How to Test the Fix:**
1. **SSRF Attack:** Run `curl -s -X POST "<your-modal-url>/v1/chat" -H "Authorization: Bearer <your_install_token>" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://127.0.0.1:8111/v1/status"}}]}]}'`
2. **Result:** The gateway should now explicitly reject it with a `400 Bad Request` saying `SSRF blocked: IP 127.0.0.1 is internal/private`.

## 5. Verbose upstream errors

**Description:** 
When an upstream provider (like Gemini or OpenAI) fails, the raw error string returned by the provider is forwarded directly to the client in the `HTTPException`. This leaks sensitive internal infrastructure details such as provider hostnames (e.g., `generativelanguage.googleapis.com`), internal paths, and routing details.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Error responses MUST NOT leak internal infrastructure details (No information leakage).
2. **Attacker Role:** Authenticated External Attacker (They have a token, but are intentionally sending bad data to trigger errors for reconnaissance).
3. **Migration Status:** Newly exposed. On `localhost` you were the only one reading the errors; on Modal, external attackers can use the errors to map your infrastructure.

**The Fix:**
Update the exception handlers in `glc/routes/chat.py` (specifically in `/v1/chat` and `/v1/embed`). The gateway still logs the raw `str(e)` to the database server-side, but it must raise a generic `HTTPException` like `502 Upstream provider error` instead of returning the raw error string to the user.

**How to Test the Fix:**
1. **Error Injection:** Run `curl -s -X POST "<your-modal-url>/v1/chat" -H "Authorization: Bearer <your_install_token>" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}'`
2. **Result:** Instead of seeing an internal googleapis error complaining about a missing key, the response should now simply be a generic `{"detail":"Upstream provider error"}` or `{"detail":"all providers unavailable"}`.

## 6. Usage and cost read (/v1/cost/by_agent, /v1/calls)

**Description:** 
The usage, per-agent cost data, and historical call ledgers are publicly accessible by default. This exposes tenant activity patterns, business intelligence, and AI cost metrics to anyone on the internet.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Usage and cost metrics must require authentication (No information leakage / Tenant isolation).
2. **Attacker Role:** Unauthenticated External Attacker.
3. **Migration Status:** Newly exposed. On `localhost`, exposing the ledger was safe because only the developer could reach it. On Modal, the data is exposed to the public internet.

**The Fix:**
We actually already applied the code fix for this during finding #2! By explicitly adding `dependencies=[Depends(_require_token)]` to the `@router.get("/v1/cost/by_agent")` and `@router.get("/v1/calls")` decorators in `glc/routes/chat.py`, we required the caller to provide the gateway's secret `install_token`. Because this gateway is a single-tenant architecture (one installation owner), requiring this token inherently scopes the results to the sole authorized tenant.

**How to Test the Fix:**
1. **Unauthenticated Test:** Run `curl -s "<your-modal-url>/v1/cost/by_agent"`. It will return a `401 Unauthorized` or `422 Unprocessable Content`.
2. **Authenticated Test:** Run `curl -s -H "Authorization: Bearer <your_install_token>" "<your-modal-url>/v1/cost/by_agent"`. It will successfully return the scoped JSON ledger.

## 7. Dump every provider key (Leak 1)

**Description:** 
Because the core gateway and the channel adapters share the exact same Python process (a monolithic design), an adapter can read `os.environ` and extract the master API keys (e.g., `GEMINI_API_KEY`) that were injected for the LLM providers. 

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Principle of Least Privilege / Secret Isolation (An adapter never holds a provider key).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker who executes arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The monolith design shares memory and environment variables across all components.

**The Fix:**
While the ultimate architectural fix requires "Per-slot Secrets plus per-tool credential issuance (Moves 2 and 3)" to run adapters out-of-process, we patched the immediate leak in `glc/main.py`. In the `lifespan` function, immediately after the providers read their keys and store them in memory, we loop through and `del os.environ[key]` for all provider API keys. Any adapter that runs later will find nothing in the environment.

**How to Test the Fix:**
1. **Snippet Test:** Run a test adapter or Python snippet inside the gateway process containing `import os; print(os.environ.get("GEMINI_API_KEY", "NOT FOUND"))`.
2. **Result:** Instead of printing the live key, it should safely print `NOT FOUND`.

## 8. Erase the audit log (Leak 2)

**Description:** 
The audit database is a plain file (`audit.sqlite`) that is fully writable by any in-process code. An attacker running a malicious payload inside an adapter can simply execute a SQL `DELETE FROM audit_log` query, instantly erasing the security history without leaving any trace of the deletion.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Audit logs must be tamper-proof (No security history erasure).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker who executes arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The SQLite database lacked append-only enforcement at the database engine level.

**The Fix:**
To patch this leak within the monolith, we implemented two layers of defense in `glc/audit/store.py` and `glc/audit/schema.sql`:
1. **Append-Only Triggers**: Added SQLite triggers (`BEFORE DELETE` and `BEFORE UPDATE`) that immediately `RAISE(ABORT)` if any code attempts to alter or drop an existing row.
2. **Cryptographic Hash Chaining**: Wrote a migration to add `prev_hash` and `curr_hash` columns. Now, `store.py` securely computes `SHA-256(prev_hash + data)` for every new log entry, cryptographically chaining them together. If a sophisticated attacker manages to drop the triggers or manually edit the `.sqlite` file on disk, the hash chain will break, making the tampering mathematically detectable.

**How to Test the Fix:**
1. **Deletion Test:** Run a Python snippet inside the gateway process: `import os, sqlite3; sqlite3.connect(os.path.join(os.getenv("GLC_CONFIG_DIR", os.path.expanduser("~/.glc")), "audit.sqlite")).execute("DELETE FROM audit_log")`.
2. **Result:** The database engine will now reject the operation with a hard SQLite `OperationalError: audit_log is append-only (deletion forbidden)`.

## 9. Escalate to owner (Leak 3)

**Description:** 
The core pairing store (which manages user trust levels) exposes an internal method called `force_pair_owner` on the `PairingStore` class. Because the gateway and channel adapters run in a shared monolithic process, an attacker who achieves prompt injection on an adapter can simply import the pairing store and execute this method to grant themselves `owner_paired` trust, instantly escalating to full administrative privileges.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Principle of Least Privilege / Control Plane Isolation (Never expose privileged methods in a shared process).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker who executes arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The monolith design exposes all class methods globally within the process memory.

**The Fix:**
While the ultimate architectural fix is Move 2 (running adapters in an isolated process so they physically cannot access the pairing store), we patched this within the monolith for Part 1. We renamed the privileged method to `_force_pair_owner`, enforcing standard Python encapsulation to prevent it from being a public API on the `PairingStore` class. All internal tests and bootstrapping scripts were refactored to use the private convention, formally removing the method from the public interface exposed to adapters.

**How to Test the Fix:**
1. **Escalation Test:** Run a Python snippet inside the gateway process: `from glc.security.pairing import get_pairing_store; get_pairing_store().force_pair_owner("telegram","attacker-id",user_handle="me")`.
2. **Result:** The execution will immediately crash with an `AttributeError`, denying the privilege escalation.

## 11. Disable the policy engine (Leak 5)

**Description:**
Python's highly dynamic nature allows any code running in the process to rebind or "monkey-patch" functions and classes. An attacker who executes a payload within an adapter can simply run `import glc.policy.engine as e; e.evaluate = lambda *a, **k: type("PolicyVerdict", (), {"action":"allow"})()`. This instantly neuters the entire security policy engine for the gateway, rendering all subsequent access control checks completely meaningless because they will permanently return "allow."

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Policy Enforcement (The policy engine must be authoritative and tamper-proof).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker who executes arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. Due to the monolith design, the adapters and the policy engine share the same Python interpreter and process memory.

**The Fix:**
**Unmitigated in Part 1 (Capstone Scope).** Because a shared Python process can *always* be monkey-patched (via `sys.modules`, `gc.get_referrers`, or direct rebinding), there is no mathematically sound way to prevent this vulnerability inside the monolith architecture. The true and only fix is architectural: we must extract the adapters and run them in a heavily restricted, separate process sandbox (Move 2 / Capstone). Since they will no longer share the gateway's memory space, they will be physically unable to monkey-patch the gateway's internal `evaluate` function.

**How to Test the Vulnerability:**
1. **Monkey-Patch Test:** Run a Python snippet inside the gateway process: `import glc.policy.engine as e; from glc.policy.schemas import PolicyVerdict; e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwn")`.
2. **Result:** Every single policy decision for the entire application will now instantly return `allow`, completely bypassing all security rules.

## 12. Kill the gateway from inside (Leak 8)

**Description:**
In a monolithic application, all components share the same Process ID (PID). An attacker running malicious code inside a channel adapter can invoke operating system commands to terminate the process it is running in via `os.kill(os.getpid(), signal.SIGTERM)` or `sys.exit()`. This instantly causes a Denial of Service (DoS) for the entire gateway and all other connected adapters.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Gateway Availability / DoS Protection (The gateway must remain alive even if an adapter misbehaves).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker executing arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The OS provides process isolation at the process boundary, but the monolith runs everything within a single boundary.

**The Fix:**
**Unmitigated in Part 1 (Capstone Scope).** Because the adapter code runs inside the exact same operating system process as the core gateway, it intrinsically possesses the authority to kill itself (and therefore, the gateway). While one could theoretically monkey-patch `os.kill` to intercept the signal, an attacker could trivially bypass it using `ctypes` to call the underlying C library, or simply call `os._exit()`. The only mathematically sound fix is architectural: implementing Separate PID Namespaces (Move 2 / Capstone). By extracting adapters into their own isolated sandboxes, they will get their own isolated PID namespace. If an attacker kills the adapter process, only the adapter dies, and the core gateway remains completely unaffected.

**How to Test the Vulnerability:**
1. **Self-Termination Test:** Run a Python snippet inside the gateway process: `import os, signal; os.kill(os.getpid(), signal.SIGTERM)`.
2. **Result:** The entire gateway API process instantly terminates.

## 13. Poison the cost ledger (Leak 10)

**Description:**
The gateway relies on the cost ledger (`glc.db.log_call`) to track API usage and bill tenants accurately. However, because the system is a monolith, an attacker who compromises a channel adapter can simply import the database module and log fabricated token usage against any victim agent they want (`glc.db.log_call(..., input_tokens=999999999, agent="victim")`). Because there is no cryptographic proof or process boundary separating the caller from the database, the ledger blindly accepts the forged write.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Ledger Integrity (Cost metrics must be unfabricated and tamper-proof).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker executing arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The monolith allows any code inside the process to call internal python functions like `log_call` without authentication.

**The Fix:**
**Unmitigated in Part 1 (Capstone Scope).** While we could theoretically require a "secret token" to be passed to `log_call`, an attacker sharing the monolithic memory space could simply read that token from memory (e.g., from `app.state` or a global variable) and forge the call anyway. The only mathematically sound fix is architectural: implementing Process Separation (Move 2 / Capstone). Once the adapters are in isolated sandboxes, the core gateway can hold a secure, private key used to cryptographically sign valid LLM calls. The isolated adapters will never see this key, making it physically impossible for them to forge ledger writes.

**How to Test the Vulnerability:**
1. **Ledger Poisoning Test:** Run a Python snippet inside the gateway process: `import glc.db; glc.db.log_call(provider="gemini", model="x", input_tokens=999999999, agent="victim")`.
2. **Result:** A massive, fabricated usage row lands in the cost ledger, completely destroying billing integrity.

## 14. Single Function, no egress wall (A3)

**Description:**
The gateway and all its channel adapters currently deploy as a single Modal `Function` (`@app.function`). In Modal, standard Functions do not support outbound network control or egress firewalls. This means any adapter—even if compromised by prompt injection—has unrestricted outbound internet access. An attacker could trivially exfiltrate sensitive data, internal tokens, or prompt context to `attacker.example.com`.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Network Egress Isolation (Untrusted code must be strictly firewall-blocked from exfiltrating data to arbitrary domains).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker executing arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The monolith relies on a standard serverless Function deployment which lacks network isolation capabilities.

**The Fix:**
**Unmitigated in Part 1 (Capstone Scope).** Because the entire application shares one Modal Function, we cannot implement an egress wall without breaking the core gateway's ability to communicate with legitimate APIs (like `googleapis.com`). The only mathematically sound fix is architectural: implementing Move 4 (Modal Sandboxes). By executing untrusted channel adapters inside ephemeral Modal Sandboxes, we can utilize the sandbox-specific `outbound_domain_allowlist` parameter to strictly enforce a network boundary, preventing any connections to unapproved, attacker-controlled domains.

**How to Test the Vulnerability:**
1. **Exfiltration Test:** Run a Python snippet inside the gateway process (or via an adapter): `import urllib.request; urllib.request.urlopen("https://example.com")`.
2. **Result:** The request fully succeeds, proving that the execution environment has unrestricted outbound internet access to arbitrary third-party servers.

## 15. One Secret for the whole Function (A4)

**Description:**
The gateway relies on a single Modal Secret (`glc-llm-keys`) that contains all master provider keys (Gemini, Groq, etc.). Because the gateway and channel adapters are deployed as a single `@app.function`, this Secret is unconditionally injected into the environment of the entire monolithic container. This is the root cause of Leak 1. While we applied a Python-level patch to scrub `os.environ` during startup, the structural flaw remains: the platform injected the master keys into a container running untrusted code.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Secret Isolation / Principle of Least Privilege (An adapter must never hold or be exposed to a provider master key).
2. **Attacker Role:** Malicious Adapter / Prompt Injection (An attacker executing arbitrary code inside an adapter context).
3. **Migration Status:** Inherited structural flaw. The monolith design forces all configuration and secrets to be mounted globally to the single execution unit.

**The Fix:**
**Unmitigated in Part 1 (Capstone Scope).** Although we scrubbed `os.environ` in Python, a sophisticated attacker could still potentially use `ctypes` to read `/proc/self/environ` or recover the strings from raw process memory before they are garbage collected. The only mathematically sound fix is architectural: implementing Per-slot Secrets and per-tool credential issuance (Moves 2 and 3). In the Capstone design, the untrusted adapter sandboxes will *never* have the `glc-llm-keys` Secret mounted to them. Instead, the gateway will issue short-lived, narrowly-scoped credentials over the network strictly on a per-tool-call basis.

**How to Test the Vulnerability:**
1. **Root Cause Analysis:** Inspect the `modal_app.py` deployment configuration: `@app.function(secrets=[modal.Secret.from_name("glc-llm-keys")])`.
2. **Result:** The deployment explicitly injects the master keys into the shared execution environment, proving the architectural vulnerability.

## 16. Non-reproducible image (A5)

**Description:**
The original `modal_app.py` built its image dynamically by using `modal.Image.debian_slim()` and chaining `.pip_install("fastapi>=0.110", ...)` with floating versions and loose dependency ranges. This completely bypassed the project's `uv.lock` file. Without a strictly pinned base image or locked dependencies, the gateway's build was non-reproducible. A shifted upstream package, a typosquatted dependency, or a compromised `debian_slim` base tag could silently introduce malicious code into the gateway directly at deployment time.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Supply Chain Integrity (Production builds must be 100% reproducible and immune to silent upstream drift).
2. **Attacker Role:** Supply Chain Attacker (An attacker compromising a PyPI dependency or a Docker base image tag).
3. **Migration Status:** Inherited structural flaw. The deployment script was written for developer convenience rather than production reproducibility.

**The Fix:**
We hardened `modal_app.py` to enforce a strictly reproducible build:
1. **Pinned Base Image**: We replaced the floating `debian_slim()` tag with a hardened, cryptographically pinned registry image (`modal.Image.from_registry("python:3.11-slim-bookworm@sha256:...")`). Even if the upstream `latest` tag is compromised, our gateway will only ever boot from this exact, verified SHA-256 digest.
2. **Locked Dependencies**: We replaced the loose `.pip_install(...)` array with `.uv_sync()`. This instructs Modal to build the Python environment strictly from the deterministic `uv.lock` file, mathematically guaranteeing that every single sub-dependency resolves to the exact same version on every deploy.

**How to Test the Fix:**
1. **Build Validation:** Run `uv run modal deploy modal_app.py`.
2. **Result:** Modal will successfully construct the image using the pinned digest and the frozen `uv.lock` dependencies.

## 17. Audit volume assumes one writer (A6)

**Description:**
The gateway relies on standard SQLite databases (`audit.sqlite` and the ledger) stored on a Modal `Volume`. However, because the app is deployed as a serverless Modal Function, it could automatically scale out to multiple concurrent containers under high load. A Modal `Volume` fundamentally does not support concurrent distributed writes, nor does it support live-reloading of data between multiple uncoordinated instances. If two containers attempt to write to the SQLite database simultaneously, the database file will silently corrupt, and the audit trail will mathematically splinter across independent container memory states.

**Audit Documentation (The Three Questions):**
1. **Broken Invariant:** Audit logs must be tamper-proof / Data Integrity (The ledger and audit trail must never corrupt or lose history under concurrent load).
2. **Attacker Role:** Denial of Service / Structural Failure (Not necessarily a targeted attack, but a critical failure when multiple requests hit simultaneously).
3. **Migration Status:** Inherited structural flaw. Moving from local development (where only one process runs) to a serverless platform introduces horizontal scaling that breaks local filesystem assumptions.

**The Fix:**
While the "Move 3/4" capstone solution would involve migrating to a true distributed database (e.g., PostgreSQL or a specialized Event Store), we patched this structural flaw for Part 1 directly in `modal_app.py`. We added `concurrency_limit=1` to the `@app.function` decorator. This formally pins the gateway to a maximum of one single container instance at any given time. By deliberately trading off horizontal scalability for data integrity, we mathematically guarantee there will only ever be a single writer manipulating the SQLite file on the Modal Volume, completely eliminating the risk of concurrent write corruption.

**How to Test the Fix:**
1. **Load Test:** Send 50 simultaneous concurrent HTTP requests to the gateway.
2. **Result:** Modal will queue the requests and process them sequentially through the single container instance, rather than spinning up multiple corrupted writers.
