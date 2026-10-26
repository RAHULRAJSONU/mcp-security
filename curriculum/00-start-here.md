# Module 00: Start Here — The Whole Idea in One Hour

> **Level:** Beginner (Java + basic Spring) | **Estimated Time:** 60 minutes, hands-on  
> **You need:** JDK 27, Docker running (for the database tests), this repository checked out.  
> **Navigation:** [📚 Curriculum Overview](README.md) | [➡️ Module 01: Threat Modeling](01-threat-modeling-and-trust-boundaries.md)

By the end of this module you will have:
1. understood **what problem** this server solves and why ordinary web security is not enough,
2. followed **one request** through the real classes, in order,
3. **run the tests** and watched security controls say no,
4. **broken a control on purpose** and watched a test catch it.

No security background is assumed. If you can read a Spring `@Service`, you can follow everything here.

---

## 1. The Problem in Plain Words

You have a database of patient records. You want an AI assistant (Claude, a chatbot, an automated agent) to answer questions such as *"who are my patients today?"* by reading it.

The assistant talks to your system through the **Model Context Protocol (MCP)**. MCP is just a standard way for an AI to call functions on your server, called **tools**. In this project a tool is a Java method with an `@McpTool` annotation:

```java
@McpTool(description = "List the patients the caller is currently assigned to.")
public CallToolResult listMyPatients() { ... }
```

That is the easy part. The hard part is that **an AI is a strange kind of client**:

| A normal client (a web page) | An AI agent |
|---|---|
| Does what the developer coded | Does what the *model decides*, which can be steered by any text it reads |
| Sends predictable requests | Can send thousands of unusual requests per minute |
| Shows results to one user | Sends results on to a third-party model provider that you cannot recall data from |
| Errors are read by developers | Errors are read by the model, which may retry or act on them |

So the question is not "is the user logged in?" but **"what is the worst thing a confused, tricked or runaway agent could do with this user's access, and how do we make that bounded, visible and reversible?"**

Everything in this repository is an answer to one of these five questions:

| # | Question | Where answered |
|---|---|---|
| 1 | **Who is calling, really?** | Modules 02–03 |
| 2 | **What exactly may they see?** | Modules 04–05 |
| 3 | **Can we prove what happened?** | Module 06 |
| 4 | **Does anything leak on the way out?** | Module 07 |
| 5 | **What if the agent misbehaves or the server is overloaded?** | Module 10 |

(Modules 01, 08 and 09 are the threat model, how to test it, and how to run it.)

---

## 2. Vocabulary You Will See Everywhere

| Term | Meaning here |
|---|---|
| **Tool** | A method an AI can call (`@McpTool`). |
| **Tenant** | One hospital. Hospital A must never see hospital B's data. |
| **Subject (`sub`)** | The human user, for example `doctor-101`. |
| **Client / agent (`azp`)** | The *software* acting for the user, for example `healthcare-mcp-client`. |
| **JWT** | A signed token the identity provider gives the user. It carries claims such as `sub`, `tenant_id`, `scope`, `azp`. |
| **Scope** | A permission written into the token, such as `patient.read` or `notes.read`. |
| **RLS** | PostgreSQL *row-level security*: the database itself hides other tenants' rows. |
| **PHI** | Protected health information. Treat every field as sensitive. |
| **Break-glass** | Emergency access that skips the normal "is this your patient?" check, but is loudly audited. |
| **Fail closed** | When something breaks, refuse, rather than allow. |

---

## 3. The Project Map

```
src/main/java/io/github/rahulrajsonu/mcpsecurity/
├── mcp/tool/        ← the AI-facing surface: @McpTool methods, error mapping, metrics
├── service/         ← SecuredPatientQueryService: the ONE door every tool uses
├── security/        ← all the checks: policy, agent registry, quota, bulkhead, tenant executor
├── persistence/     ← repositories (JPA and plain JDBC)
├── config/          ← Spring configuration and @ConfigurationProperties
└── exception/       ← exceptions that know their own error code

src/main/resources/
├── application.yaml        ← every setting, with comments
└── db/migration/           ← Flyway SQL: tables, RLS policies, agents, audit columns
    db/seed/                ← demo data (local and test only)

src/test/java/…/            ← unit tests (*Test) and database integration tests (*IT)
docs/                       ← operator guides: agent-registry, observability, scaling
ops/prometheus-alerts.yml   ← ready-made alert rules
```

**The one rule to remember:** tools contain almost no logic. They hand the work to `SecuredPatientQueryService.guarded(...)`, and that method is where the security happens.

---

## 4. Follow One Request (Guided Code Tour)

Scenario: `doctor-101` asks their assistant *"Show me patient-400's summary."* The assistant calls the tool `getPatientSummary("patient-400")`. Open each file as you read.

### Step 1 — The HTTP edge (before any of your code)

`config/SecurityConfig.java` builds the filter chain. In order:

| Filter | What it does |
|---|---|
| `RequestIdFilter` | Gives the request an id for log correlation (`X-Request-ID`). |
| `RateLimitFilter` | Per-IP and per-token flood guard. |
| `RequireHttpsFilter` | Refuses plain HTTP in production. |
| Spring's bearer-token filter | Validates the JWT signature, issuer, audience and age. |
| `CertificateBoundTokenFilter` | With mTLS, checks the token is bound to the caller's certificate. |

If any of these says no, your tool method never runs.

### Step 2 — The tool method

`mcp/tool/PatientMcpTools.java`:

```java
@McpTool(description = "Retrieve an authorized patient's summary. ...")
public CallToolResult getPatientSummary(String patientId, String purpose, String justification) {
    return results.call(() ->
        patientQueryService.getSummary(context(purpose, justification), patientId));
}
```

`context(...)` reads the verified token from Spring's `SecurityContextHolder`, and `ClinicalPrincipalResolver` turns it into a **`ClinicalPrincipal`** (subject, tenant, scopes, client, `acr`, actor). `results.call(...)` wraps success in a `CallToolResult` and turns any exception into a safe error (Step 6).

> **Why is `purpose` a parameter?** Because the *model* fills in tool arguments. Anything the model chooses must be treated as untrusted input. Hold that thought for break-glass (Module 04).

### Step 3 — The one door

`service/SecuredPatientQueryService.java`, method `guarded`:

```java
requireWellFormed(patientId);            // 1. reject weird ids early
quota.acquire(context.principal());      // 2. has this agent made too many calls?

T result = bulkhead.run(() ->            // 3. is the server too busy?
    tenantExecutor.execute(context.principal(), () -> {   // 4. open a tenant-scoped transaction
        agentPolicy.requireActive(context.principal());   // 5. is this agent approved?
        T value = read.get();                             // 6. policy + the actual read
        auditor.appendAllowed(context, patientId, category);  // 7. write the audit row
        return value;
    }));                                  // 8. COMMIT: data and audit row together

auditor.logAllowed(context, patientId, category);   // 9. log line + metric
return result;
```

Read it twice. Each numbered line is a gate; each has its own module:

| Line | Gate | Class | Module |
|---|---|---|---|
| 1 | Input validation | `requireWellFormed` | 07 |
| 2 | Per-agent quota | `AgentQuota` | 10 |
| 3 | Load shedding | `CallBulkhead` | 10 |
| 4 | Tenant isolation | `TenantScopedExecutor` | 05 |
| 5 | Agent registry | `AgentAccessPolicy` | 10 |
| 6 | Authorization | `PatientAccessPolicy` | 04 |
| 7–8 | Fail-closed audit | `AccessAuditor` | 06 |

### Step 4 — The tenant fence

`security/TenantScopedExecutor.java` is eight lines that matter most:

```java
@Transactional(propagation = Propagation.REQUIRES_NEW)
public <T> T execute(ClinicalPrincipal principal, Supplier<T> operation) {
    ...
    entityManager.createNativeQuery("SELECT set_config('app.tenant_id', :tenantId, true)")
        .setParameter("tenantId", principal.tenantId()).getSingleResult();
    return operation.get();
}
```

It tells PostgreSQL "for this transaction only, the tenant is `hospital-A`". The tables have an RLS policy, written in SQL, that says `USING (tenant_id = current_setting('app.tenant_id', true))`. So even if a developer forgets a `WHERE tenant_id = ...`, the **database** returns only hospital A's rows. The `true` (transaction-local) means the setting disappears at commit, so a pooled connection cannot carry it to the next request.

### Step 5 — The decision

`security/PatientAccessPolicy.java` checks the scope for the data category, then the purpose: `TREATMENT` needs an active assignment of this doctor to this patient; `EMERGENCY` needs the break-glass rules. Any failure throws `PatientAccessDeniedException`, with **the same message for every cause**, so a caller cannot probe which patients exist.

### Step 6 — The answer, or the safe error

Success becomes a normal `CallToolResult`. Any failure becomes this and nothing more:

```json
{ "error": "access_denied", "message": "Access denied", "retryable": false }
```

No stack trace, no SQL, no hint about *why*. The reason is for operators (logs and metrics), not for the model.

### Step 7 — What the operator sees

The same request left behind:
- one row in `access_events` (who, which agent, which patient, outcome),
- one log line on `AUDIT.patient-access`,
- counters on `:8081/actuator/prometheus` (`clinical_patient_access_total`, `mcp_tool_calls_total`, …).

---

## 5. Hands-On Lab 0: Run It and Watch It Say No

You do not need an identity provider to learn. The tests build fake tokens and call the tools directly against a real PostgreSQL started by Testcontainers.

**0.1 — Check your setup**

```bash
docker info            # must work
./mvnw -v              # JDK 27
```

**0.2 — Run the fast unit tests (no Docker)**

```bash
./mvnw test
```

**0.3 — Run one integration test (Docker)**

```bash
./mvnw verify -Dit.test=AgentRegistryIT -Dtest=NoSuchTest -Dsurefire.failIfNoSpecifiedTests=false
```

The first run downloads the PostgreSQL image. When it finishes, scroll the output and find lines like these (they are the audit trail):

```text
AUDIT.agent-access   : agent_denied reason=not_approved tenant=hospital-A subject=doctor-101 client=suspended-client
AUDIT.patient-access : patient_access outcome=DENIED subject=doctor-101 tenant=hospital-A patient=patient-400 client=suspended-client ...
```

Notice what is *not* there: no patient name, no diagnosis. Logs carry identifiers and outcomes, never clinical content.

**0.4 — Read a real test**

Open `src/test/java/io/github/rahulrajsonu/mcpsecurity/AgentRegistryIT.java`. The helper `loginAs(...)` builds a fake JWT and puts it in Spring's `SecurityContextHolder`. A test then calls the tool like any Java method:

```java
loginAs("doctor-101", "hospital-A", "patient.read", "suspended-client");
assertDenied(patientTools.listMyPatients());
```

That is the whole testing technique used in this repository.

---

## 6. Hands-On Lab 0.5: Break a Control on Purpose

The best way to believe a control works is to remove it and watch a test fail.

Each of these was run while writing this module; the failures below are real.

| Break this | In file | Run | What happens |
|---|---|---|---|
| Delete the line `agentPolicy.requireActive(...)` | `SecuredPatientQueryService.java` | `./mvnw verify -Dit.test=AgentRegistryIT` | 7 of 11 tests fail, for example `suspendedAgentIsRefused`: the suspended agent can now read. |
| Delete the `set_config(...)` call (the whole `createNativeQuery` statement) | `TenantScopedExecutor.java` | `-Dit.test=TenantScopedExecutorIT` | `shouldIsolateTenantsAcrossTransactions` fails. Note the design: forgetting the tenant gives you *nothing*, not *everything*, because RLS sees no tenant and hides every row. |
| Remove the `throw new AuditUnavailableException(ex);` line in `appendAllowed` | `AccessAuditor.java` | `-Dit.test=AuditFailClosedIT` | `anAllowedReadIsRefusedWhenTheAuditWriteFails` fails: data is returned although the audit write failed. |
| Change `"Access denied", false` to `true` in `ACCESS_DENIED` | `ToolCallResponse.java` | `./mvnw test -Dtest=ToolCallResponseTest` | `onlyTransientFailuresAreRetryable` fails: the model would be told to retry a refusal. |

After each experiment, undo your change (`git checkout -- <file>`).

---

## 7. How the Curriculum Is Organised

Every later module follows the same shape, so you always know where you are:

1. **The problem** — a concrete attack or failure, in plain words.
2. **The idea** — the defence, with a small diagram.
3. **The code** — the real classes, with links.
4. **Run it** — commands and expected output.
5. **Break it** — a change that should make a test fail.
6. **Recap** — a checklist of what you can now explain.

Suggested paths:

| You are… | Read |
|---|---|
| A Java/Spring developer new to security | 00 → 01 → 04 → 05 → 06 → 10, then the rest |
| A security reviewer | 01 → 03 → 05 → 06 → 09 → 10 (Section 11: open gaps) |
| An SRE | 09 → 10 (Sections 7 and 9) → `docs/scaling.md` |

---

## 8. Recap Checklist

You should now be able to say, in your own words:

- [ ] Why an AI agent needs stricter controls than a web page.
- [ ] What a tool, a tenant, a scope and an agent (client) are.
- [ ] Which class every tool call passes through, and the order of its gates.
- [ ] Why the database, not just Java code, enforces tenant isolation.
- [ ] Why every failure looks the same to the caller but different to the operator.
- [ ] How to run a test that proves a control works, and how to break it on purpose.

[➡️ Continue to Module 01: Threat Modeling & Trust Boundaries](01-threat-modeling-and-trust-boundaries.md)
