# Module 02: Transport Layer Security & Ingress Hardening

> **Level:** Systems & Network Security | **Estimated Reading Time:** 20 mins  
> **Prerequisites:** Module 01, basic understanding of HTTP headers, TLS, and reverse proxies.  
> **Navigation:** [⬅️ Module 01: Threat Modeling & Trust Boundaries](01-threat-modeling-and-trust-boundaries.md) | [➡️ Module 03: Token Binding & Authentication](03-authentication-and-token-binding.md)

---

## 1. Why Standard Web Defaults Fail for AI APIs

In traditional consumer web applications, when a user visits `http://example.com`, the server responds with:
```http
HTTP/1.1 301 Moved Permanently
Location: https://example.com/
```
In browser navigation, this is acceptable for unauthenticated page visits. 

**In API and AI Agent tool calls, this is a catastrophic security flaw.**

When an AI client (such as Claude Desktop, an autonomous agent worker, or an MCP proxy) makes a request over plain HTTP:
1. The request payload already includes the sensitive query (`{"patientId": "patient-400"}`).
2. The HTTP header already carries the bearer token: `Authorization: Bearer eyJhbGci...`.
3. If this crosses an unencrypted local Wi-Fi, hospital intranet, or public connection, **the credentials and patient queries have already been sniffed in cleartext**.
4. Issuing a `301` or `302` redirect does not undo the packet transmission. Furthermore, HTTP clients often strip or dangerously alter headers on redirects.

### The Architectural Rule
> **For APIs handling sensitive data, never redirect plain HTTP. Fail hard immediately.**

---

## 2. Fail-Hard HTTPS Enforcement: `RequireHttpsFilter`

In this repository, plain HTTP requests are intercepted at the very beginning of the filter chain and terminated with an immediate `403 Forbidden`.

Let's inspect [`RequireHttpsFilter.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/security/RequireHttpsFilter.java#L23-L44):

```java
public class RequireHttpsFilter extends OncePerRequestFilter {

    private final RequestMatcher exempt;

    public RequireHttpsFilter(RequestMatcher exempt) {
        this.exempt = exempt;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {

        // Check if the connection is already TLS, or exempt (internal management port)
        if (request.isSecure() || exempt.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        // Fail hard without redirecting: surfaces misconfigurations immediately
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
```

### Understanding `request.isSecure()` and `X-Forwarded-Proto`
In a cloud deployment (Kubernetes, AWS ALB, Cloudflare), TLS is often terminated at the reverse proxy or ingress gateway:
1. The client connects to Ingress via `https://api.healthcare.org/mcp`.
2. The Ingress forwards plain HTTP internally to the Spring Boot Pod on `http://10.244.0.15:8080/mcp`.
3. The Ingress sets the header: `X-Forwarded-Proto: https`.

Spring Boot's `server.forward-headers-strategy=native` (or `framework`) inspects `X-Forwarded-Proto`. When set to `https`, `request.isSecure()` evaluates to `true`.

> [!CRITICAL]
> **Ingress Spoofing Vulnerability:** If your ingress controller accepts `X-Forwarded-Proto` from external clients without overwriting it, an attacker can send requests over plain HTTP with a spoofed header `X-Forwarded-Proto: https`, bypassing TLS enforcement. Your edge ingress must be configured to unconditionally overwrite `X-Forwarded-Proto` based on the actual edge handshake.

---

## 3. Port Segregation: Public API vs Management Actuator

Spring Boot Actuator endpoints provide powerful monitoring, metrics, and diagnostics. However, if exposed to the public internet or accessible via the same port as the MCP server, they create severe vulnerabilities:
- `/actuator/env`: Can leak environment variables, database credentials, and API keys.
- `/actuator/heapdump`: Dumps process memory containing decrypted tokens and PHI.
- `/actuator/prometheus`: Exposes operational metrics that attackers can use to map internal traffic patterns.

### The Dual-Port Architecture
In this repository, the application binds to **two independent ports**:
- **Port 8080 (`PORT`):** Public MCP API listener.
- **Port 8081 (`MANAGEMENT_PORT`):** Internal management and health probe listener.

```
Internet / Agent Hosts
         │
         ▼ (Port 8080 ONLY)
┌─────────────────────────────────────────────────────────────┐
│ Spring Boot Application Container                           │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ Port 8080: Public Listener                          │   │
│   │  - /mcp (Requires OAuth 2.0 / mTLS)                 │   │
│   │  - /.well-known/oauth-protected-resource (Metadata) │   │
│   │  - /actuator/** -> 401 UNAUTHORIZED (BLOCKED!)      │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ Port 8081: Management Listener (Internal Pod Only)  │   │
│   │  - /actuator/health/liveness (Permitted)            │   │
│   │  - /actuator/health/readiness (Permitted)           │   │
│   │  - /actuator/prometheus (Permitted)                 │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         ▲
         │ (Port 8081 ONLY)
Kubernetes Kubelet / Internal Prometheus Scraper
```

Let's examine how this is enforced in [`SecurityConfig.java`](file:///c:/ws/health-mcp-client/src/main/java/io/github/rahulrajsonu/mcpsecurity/config/SecurityConfig.java#L47-L65):

```java
// Matcher that only matches requests arriving on the management port (8081)
RequestMatcher onManagementPort = request -> {
    Integer managementPort = environment.getProperty("local.management.port", Integer.class);
    return managementPort != null && managementPort == request.getLocalPort();
};

RequestMatcher actuator = RequestMatchers.allOf(
        PathPatternRequestMatcher.withDefaults().matcher("/actuator/health/**"),
        onManagementPort);

RequestMatcher metrics = RequestMatchers.allOf(
        PathPatternRequestMatcher.withDefaults().matcher("/actuator/prometheus"),
        onManagementPort);

return http
        .authorizeHttpRequests(auth -> auth
                // Allow health and metrics ONLY on the management port
                .requestMatchers(actuator, metrics).permitAll()

                // Require authentication for MCP tools on the public port
                .requestMatchers("/mcp", "/mcp/**").authenticated()

                // DENY EVERYTHING ELSE BY DEFAULT
                .anyRequest().denyAll()
        )
        // ...
```

---

## 4. Hardened Security Headers & Caching Controls

When an AI tool returns clinical data, intermediate HTTP caches (CDNs, proxy caches, browser caches) must **never** store the response.

### 1. Zero-Caching (`Cache-Control: no-store`)
Under HIPAA § 164.312(a)(2)(iv) and general privacy laws, temporary storage of PHI on untrusted caching proxies constitutes an unauthorized disclosure.

Spring Security and application configuration guarantee:
```http
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
```

### 2. Content Security Policy (CSP) & Frame Options
Even though MCP is primarily a JSON-RPC protocol, hardened HTTP response headers prevent UI-redirection attacks, framing, and content-type sniffing:

```java
// Configured in SecurityConfig.java
.headers(headers -> headers
        .contentSecurityPolicy(csp ->
                csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
        .frameOptions(frame -> frame.deny())
)
```

---

## 5. Proving It: Integration Tests

How do we prove these controls actually work in production? We write automated integration tests using real HTTP clients.

### Proving Port Separation: `SecurityEndpointsIT.java`
Inspect [`SecurityEndpointsIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/SecurityEndpointsIT.java#L41-L56):

```java
@Test
void healthAndMetricsAreServedOnlyOnTheManagementPort() throws Exception {
    // 1. Probes on the management port succeed (HTTP 200)
    assertThat(get(managementPort, "/actuator/health/readiness").statusCode()).isEqualTo(200);
    assertThat(get(managementPort, "/actuator/prometheus").body()).contains("jvm_memory_used_bytes");

    // 2. The same probes on the public port FAIL (HTTP 401 Unauthorized)
    assertThat(get("/actuator/health").statusCode()).isNotEqualTo(200);
    assertThat(get("/actuator/prometheus").statusCode()).isNotEqualTo(200);
}

@Test
void responsesAreNeverCacheable() throws Exception {
    // Proves Cache-Control contains no-store
    assertThat(get("/mcp").headers().firstValue("Cache-Control").orElse(""))
            .contains("no-store");
}
```

### Proving Plain HTTP Refusal: `HttpsEnforcementIT.java`
Inspect [`HttpsEnforcementIT.java`](file:///c:/ws/health-mcp-client/src/test/java/io/github/rahulrajsonu/mcpsecurity/HttpsEnforcementIT.java#L35-L48):

```java
@Test
void plainHttpIsForbiddenOnPublicPort() throws Exception {
    // In prod profile, plain HTTP returns 403 Forbidden, not a redirect (301/302)
    HttpResponse<String> response = client.send(
            HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/mcp")).GET().build(),
            HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(403);
}
```

---

## 6. Hands-On Lab: Test the Perimeter Controls

### Lab 2.1: Verify Port Separation with Curl
1. Start the server locally:
   ```bash
   SPRING_PROFILES_ACTIVE=local ./mvnw spring-boot:run
   ```
2. In a separate terminal, test accessing metrics on the public port (8080):
   ```bash
   curl -i http://localhost:8080/actuator/prometheus
   ```
   *Expected result: `401 Unauthorized` or `403 Forbidden`.*
3. Now test accessing metrics on the internal management port (8081):
   ```bash
   curl -i http://localhost:8081/actuator/prometheus
   ```
   *Expected result: `200 OK` with Prometheus metric counters.*

---

[➡️ Proceed to Module 03: Token Binding & Authentication](03-authentication-and-token-binding.md)
