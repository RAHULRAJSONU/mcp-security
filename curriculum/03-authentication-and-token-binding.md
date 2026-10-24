# Module 03: Token Binding & Cryptographic Authentication

> **Level:** Cryptographic Identity & Auth | **Estimated Reading Time:** 25 mins  
> **Prerequisites:** Module 01, Module 02, familiarity with OAuth 2.0, JWTs, and PKI.  
> **Navigation:** [⬅️ Module 02: Transport & Edge Security](02-transport-and-edge-security.md) | [➡️ Module 04: Contextual Authorization & Break-Glass](04-contextual-authorization-and-breakglass.md)

---

## 1. The Bearer Token Dilemma in AI Tools

In classical OAuth 2.0 (RFC 6749), tokens are **bearer tokens**:
> *"Whoever holds the token can spend the token."*

In an AI Agent environment, bearer tokens are hazardous:
1. **Local Agent Disk Storage:** AI desktop clients (e.g., Claude Desktop, Cursor, OpenDevin) store MCP configurations and environment variables in local JSON files on the developer's laptop (`claude_desktop_config.json`).
2. **Context Window Leakage:** If an agent outputs its environment or executes a tool that dumps headers, the bearer token appears directly in the LLM context window.
3. **Third-Party Telemetry:** AI tool invocation logs, agent traces, and observability platforms (LangSmith, Helicone) frequently ingest HTTP headers, exposing raw bearer tokens to third-party SaaS providers.
4. **Instant Replay:** If an attacker extracts a bearer token from a log or prompt injection, they can replay it from any machine in the world until it expires.

To secure AI tools, we must introduce **Sender-Constrained Tokens** and **Strict Token Validation**.

---

## 2. Principle of User-Delegated Tokens

AI agents must **never** connect to sensitive databases using shared service accounts (such as OAuth `client_credentials` grant).

```
❌ ANTI-PATTERN: SHARED SERVICE CREDENTIAL
[AI Agent / MCP Host] ──── Uses "healthcare-service-key" ────► [MCP Server] ────► [DB: Full Access]
(A single prompt injection can read ANY patient across ALL hospitals)

✅ HARDENED PATTERN: USER-DELEGATED OIDC TOKEN
[Clinician Alice] ── Browser Login (MFA) ──► [Keycloak IdP]
       │                                            │
       ▼                                            ▼
[AI Agent Host] ◄──── Short-Lived Access Token ─────┘
  (Holds ONLY Alice's delegated token: sub=alice, tenant=hospital-A)
       │
       ▼ (Tool Call with Alice's Token)
[MCP Server] ── Verifies Alice's Scopes & Tenant ──► [DB: Returns ONLY Alice's Patients]
```

When the agent invokes an MCP tool, the server inspects the caller's JWT to extract:
- `sub`: The human clinician's unique identifier (e.g., `doctor-101`).
- `tenant_id`: The organization or hospital they belong to (e.g., `hospital-A`).
- `scope`: The exact granular operations permitted.

See [`ClinicalPrincipalResolver.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/ClinicalPrincipalResolver.java#L15-L53):

```java
@Component
public class ClinicalPrincipalResolver {

    public ClinicalPrincipal resolve(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwtAuth) || !jwtAuth.isAuthenticated()) {
            throw new AccessDeniedException("Authenticated JWT required");
        }

        var jwt = jwtAuth.getToken();
        String subject = jwt.getSubject();
        String tenantId = jwt.getClaimAsString("tenant_id");
        String scopeClaim = jwt.getClaimAsString("scope");

        if (subject == null || subject.isBlank()) {
            throw new AccessDeniedException("Missing required subject claim");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new AccessDeniedException("Missing required tenant claim");
        }

        Set<String> scopes = scopeClaim == null ? Set.of()
                : Arrays.stream(scopeClaim.split("\\s+"))
                        .filter(s -> !s.isBlank())
                        .collect(Collectors.toUnmodifiableSet());

        return new ClinicalPrincipal(subject, tenantId, scopes);
    }
}
```

---

## 3. Strict Audience Validation (`aud`)

### The Attack: Cross-Service Token Confusion
Imagine an enterprise with two services:
1. `payroll-service`
2. `healthcare-mcp-server`

Both trust the same central Keycloak IdP. If a user logs into `payroll-service`, they receive a valid JWT signed by Keycloak. If `healthcare-mcp-server` only checks the cryptographic signature and issuer, an attacker can take that `payroll-service` token and submit it to `healthcare-mcp-server`.

### The Defense
In [`JwtSecurityConfig.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfig.java#L77-L99), the server enforces strict audience matching:

```java
static OAuth2TokenValidator<Jwt> audienceValidator(String expectedAudience) {
    if (expectedAudience == null || expectedAudience.isBlank()) {
        throw new IllegalArgumentException("Expected JWT audience must not be blank");
    }

    return jwt -> {
        if (jwt.getAudience() != null && jwt.getAudience().contains(expectedAudience)) {
            return OAuth2TokenValidatorResult.success();
        }

        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "Token audience is not accepted", null)
        );
    };
}
```
If `aud` does not explicitly include `healthcare-mcp-server`, the token is rejected immediately.

---

## 4. Limiting the Blast Radius: Maximum Token Lifetime

In a stateless architecture, there is no server-side "session table" to invalidate when a clinician closes their laptop. **Token expiration (`exp`) is the only automatic logoff.**

If an IdP misconfiguration issues tokens valid for 24 hours or 30 days, a leaked token remains dangerous for weeks.

In [`JwtSecurityConfig.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/filter/JwtSecurityConfig.java#L52-L75), we enforce a hard ceiling on token lifetime (`JWT_MAX_LIFETIME`, default `PT15M` = 15 minutes):

```java
static OAuth2TokenValidator<Jwt> maxLifetimeValidator(Duration maxLifetime) {
    return jwt -> {
        if (jwt.getIssuedAt() != null
                && jwt.getExpiresAt() != null
                && Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())
                        .compareTo(maxLifetime) <= 0) {
            return OAuth2TokenValidatorResult.success();
        }

        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "Token lifetime is missing or too long", null)
        );
    };
}
```

Even if the IdP signs a token with `exp - iat = 8 hours`, our MCP server rejects it with `invalid_token`.

---

## 5. Sender-Constrained Tokens: RFC 8705 Mutual TLS Binding

To definitively prevent token theft and replay, the token must be **cryptographically bound** to the client.

### How RFC 8705 Certificate-Bound Tokens Work
1. The client (e.g., an MCP proxy or agent host) establishes an **mTLS connection** using its private key and client certificate.
2. When requesting a token from the IdP, the IdP calculates the SHA-256 thumbprint of the client certificate:
   $$\text{thumbprint} = \text{Base64Url}(\text{SHA-256}(\text{DER}(\text{Certificate})))$$
3. The IdP embeds this thumbprint in the JWT under the Confirmation claim:
   ```json
   {
     "sub": "doctor-101",
     "cnf": {
       "x5t#S256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
     }
   }
   ```
4. When the client sends the token to our MCP server over mTLS, [`CertificateBoundTokenFilter.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/CertificateBoundTokenFilter.java#L44-L86) verifies that the certificate presented on the TLS connection matches `cnf.x5t#S256`:

```java
private boolean isAcceptable(Jwt token, HttpServletRequest request) {
    String boundThumbprint = boundThumbprint(token);
    if (boundThumbprint == null) {
        return !requireBoundTokens;
    }

    Object attribute = request.getAttribute(CERTIFICATE_ATTRIBUTE);
    if (!(attribute instanceof X509Certificate[] chain) || chain.length == 0) {
        return false;
    }

    String presented = thumbprint(chain[0]);

    // Constant-time byte comparison prevents side-channel timing attacks
    return presented != null && MessageDigest.isEqual(
            boundThumbprint.getBytes(StandardCharsets.US_ASCII),
            presented.getBytes(StandardCharsets.US_ASCII));
}
```

> [!TIP]
> **Why this stops token theft:** If an attacker steals this JWT from an agent's log file or memory, they cannot replay it against the server. To replay the token, the attacker must also possess the client's private key to complete the mTLS handshake.

---

## 6. Proving It: Integration Tests

### Proving Certificate Binding: `MutualTlsIT.java`
Inspect [`MutualTlsIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/MutualTlsIT.java#L59-L81):

```java
@Test
void clientWithoutCertificateCannotConnect() throws Exception {
    HttpClient client = client(null); // No client cert

    // Handshake fails before HTTP response
    assertThatThrownBy(() -> get(client, "/.well-known/oauth-protected-resource"))
            .isInstanceOf(IOException.class);
}

@Test
void clientWithCertificateTheServerDoesNotTrustCannotConnect() throws Exception {
    HttpClient client = client("rogue.p12"); // Untrusted cert

    assertThatThrownBy(() -> get(client, "/.well-known/oauth-protected-resource"))
            .isInstanceOf(IOException.class);
}

@Test
void trustedClientReachesTheApplicationWhichStillDemandsAToken() throws Exception {
    HttpClient client = client("client.p12"); // Valid client cert

    // Handshake succeeds, but HTTP 401 proves token is still demanded!
    assertThat(get(client, "/mcp").statusCode()).isEqualTo(401);
}
```

---

## 7. Hands-On Lab: Test Token Validation Logic

Run the unit tests verifying token audience and maximum lifetime rules:
```bash
./mvnw test -Dtest=JwtSecurityConfigTest,TokenLifetimeValidatorTest
```

Notice how tests assert:
1. Tokens with missing audience are rejected.
2. Tokens for foreign audiences (`some-other-service`) are rejected.
3. Tokens with `exp - iat = 16 minutes` are rejected when `maxLifetime = PT15M`.

---

[➡️ Proceed to Module 04: Contextual Authorization & Break-Glass](04-contextual-authorization-and-breakglass.md)
