# Hands-on guide: Cloud-IAM, a real login, and Claude Desktop

This guide walks you through running the server against a **real identity provider** and then talking to it from
**Claude Desktop**, so you can watch the access-control policy work with your own hands. It uses
[Cloud-IAM](https://www.cloud-iam.com), which hosts Keycloak and has a free plan. Any Keycloak (or another OIDC
provider that can add the claims in [Access token requirements](../README.md#access-token-requirements)) works the same way.

> Everything here is for **learning, with synthetic data**. Do not point real patient data at a setup built from this
> guide. Read the [safety assumptions](../README.md#safety-assumptions) first.

What you will build:

```
Claude Desktop ──stdio──> mcp-remote ──HTTP + OAuth──> this server (:8080) ──> PostgreSQL (row-level security)
                               │                              │
                               └──── browser login ──> Keycloak on Cloud-IAM (issues the tokens)
```

Time: about 45 minutes the first time.

## What you need

- JDK 27 and the Maven wrapper (`./mvnw`)
- PostgreSQL running locally, and `psql`
- Node.js 18+ (for the sign-in helper and `npx`)
- A free Cloud-IAM account, and Claude Desktop

## Part 1: Create the identity provider

### 1.1 Create a deployment

1. Sign in to the Cloud-IAM console and create a deployment on the **Free** plan.
2. Open the deployment summary. Note the **Deployment admin url**. It looks like
   `https://<host>/auth/admin/<realm>/console/`. The realm name is the same as the deployment name.
3. Your issuer is `https://<host>/auth/realms/<realm>`. Check that it works:

   ```bash
   curl -s https://<host>/auth/realms/<realm>/.well-known/openid-configuration | head -c 200
   ```

4. Click **Keycloak console** in the summary page to open the admin console already signed in.

Everything below happens in that realm. Replace `<realm>` and `<host>` with your values.

### 1.2 Create the five scopes

The server reads authorisation from a space-separated `scope` claim. Under **Client scopes → Create client scope**,
create these five (one at a time):

| Name | Purpose |
|---|---|
| `patient.read` | Patient summary and roster |
| `medication.read` | Medications |
| `notes.read` | Clinical notes |
| `patient.break_glass` | Emergency access |
| `audit.read` | The two audit tools |

For each: leave **Type** as `None` and turn **Include in token scope** **On** (it is off by default, and without it the
scope never appears in the token).

### 1.3 Create the client

A *public* client with no secret, so there is nothing to leak.

1. **Clients → Create client**. Client ID `healthcare-live-test`, type OpenID Connect.
2. Capability config: **Client authentication Off**, keep **Standard flow**, and tick
   **OAuth 2.0 Device Authorization Grant**.
3. Save, then under **Settings → Valid redirect URIs** add `http://localhost:3334/oauth/callback` (used by Claude
   Desktop in Part 5) and save again.
4. **Client scopes → Add client scope**: add the five scopes from 1.2 as **Optional**. Optional means a token only
   carries a scope when the client asks for it, which is how you practise least privilege.

### 1.4 Add the two claims the server needs

Open **Clients → healthcare-live-test → Client scopes → healthcare-live-test-dedicated → Add mapper → By
configuration**:

1. **Audience** mapper. Name `mcp-audience`, **Included Custom Audience** `healthcare-mcp-server`, add to access token
   On. Without this the server rejects the token: the audience check is what stops a token minted for another service.
2. **User Attribute** mapper. Name `tenant-id`, **User Attribute** `tenant_id`, **Token Claim Name** `tenant_id`,
   type String, add to access token On.

### 1.5 Let administrators set a tenant on users

Keycloak hides custom attributes by default. In **Realm settings → General**, set **Unmanaged Attributes** to
**Only administrators can write**. Choosing "Enabled" would let users edit their own `tenant_id`, which defeats
tenant isolation.

### 1.6 Create practice users

Create a few users under **Users → Add user**, give each a password under **Credentials**, and set the `tenant_id`
attribute under **Attributes**:

| Username | `tenant_id` | Practice role |
|---|---|---|
| `dr-ada` | `hospital-A` | Clinician with an active assignment to one patient |
| `dr-ben` | `hospital-A` | Clinician with two active assignments |
| `dr-cara` | `hospital-B` | Clinician at another hospital |
| `auditor-1` | `hospital-A` | Reviews the audit trail |

Use dedicated users rather than the realm `admin` account. A user's **scopes are chosen when they sign in** (Part 3),
so the same user can practise with narrow and wide tokens.

## Part 2: Run the server against it

### 2.1 A scratch database

```bash
export PGPASSWORD=postgres
psql -h localhost -U postgres -c "CREATE DATABASE patient_db_live"
psql -h localhost -U postgres -c "CREATE ROLE healthcare_app LOGIN PASSWORD 'postgres'"   # skip if it exists
```

### 2.2 Start the app

Put your settings in a git-ignored `.env` file in the project root. Copy `.env.example` and fill in your realm. It holds
no secrets here, because the client is public:

```bash
# .env
OIDC_ISSUER=https://<host>/auth/realms/<realm>
JWT_AUDIENCE=healthcare-mcp-server
JWT_MAX_LIFETIME=PT15M
OIDC_CLIENT_ID=healthcare-live-test
SCOPES="openid patient.read medication.read notes.read patient.break_glass audit.read"
SPRING_PROFILES_ACTIVE=local
POSTGRES_DB=patient_db_live
APP_PUBLIC_URL=http://localhost:8080
```

Spring Boot does not read `.env` by itself, so load it into your shell first (keep the quotes around `SCOPES`, because
it contains spaces), then build and run:

```bash
set -a; . ./.env; set +a
./mvnw -q -DskipTests package
java -jar target/mcp-security-0.0.1-SNAPSHOT.jar
```

`.gitignore` already excludes `.env`. Check with `git check-ignore -v .env` before your first commit. In IntelliJ, the
EnvFile plugin can load the same file into a run configuration.

The `local` profile applies the migrations and the synthetic seed data. The app contacts your issuer at startup and
refuses to boot if it cannot, which is deliberate. Check:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/mcp          # 401, no token
curl -s http://localhost:8081/actuator/health/readiness                              # {"status":"UP"}
curl -s http://localhost:8080/.well-known/oauth-protected-resource                   # names your realm
```

### 2.3 Map your users to patients

This is the step people miss. The server identifies a clinician by the token's **`sub`**, which Keycloak makes a UUID
(not `doctor-101`, which is just seed data for the automated tests). Find each user's ID in the admin console
(**Users → the user → ID**), then grant assignments. Connect as `postgres` (the owner bypasses row-level security,
which is what you want for setup):

```sql
-- patients in the seed data: patient-400, patient-500 (hospital-A), patient-600 (hospital-B)
INSERT INTO patient_assignments (id, tenant_id, clinician_id, patient_id, status, valid_from, valid_until) VALUES
 ('a-ada-400',  'hospital-A', '<dr-ada UUID>',  'patient-400', 'ACTIVE',  now() - interval '1 day',  now() + interval '30 days'),
 ('a-ada-500',  'hospital-A', '<dr-ada UUID>',  'patient-500', 'REVOKED', now() - interval '10 days', NULL),
 ('a-ben-400',  'hospital-A', '<dr-ben UUID>',  'patient-400', 'ACTIVE',  now() - interval '1 day',  now() + interval '30 days'),
 ('a-ben-500',  'hospital-A', '<dr-ben UUID>',  'patient-500', 'ACTIVE',  now() - interval '1 day',  now() + interval '30 days'),
 ('a-cara-600', 'hospital-B', '<dr-cara UUID>', 'patient-600', 'ACTIVE',  now() - interval '1 day',  now() + interval '30 days');
```

`auditor-1` needs no assignment: the audit tools use the `audit.read` scope, not an assignment.

## Part 3: Get a real token

`scripts/device-login.js` uses the device authorization grant. It prints a URL and a code, you sign in in your own
browser, and no password ever passes through the script.

The script reads `OIDC_ISSUER` and `OIDC_CLIENT_ID` from the environment, so load `.env` first
(`set -a; . ./.env; set +a`). `SCOPES` in `.env` is only the default. Override it on the command line to practise with
a narrower or wider token:

```bash
# a clinician with ordinary read access
SCOPES="openid patient.read medication.read notes.read" node scripts/device-login.js

# the same kind of user, now allowed to declare an emergency
SCOPES="openid patient.read medication.read notes.read patient.break_glass" node scripts/device-login.js

# the auditor
SCOPES="openid audit.read" node scripts/device-login.js
```

Open the URL, enter the code, and sign in as the user you want. The script then prints the claims the server will see.
**Check three things every time**:

- `aud` contains `healthcare-mcp-server`
- `tenant_id` is present and correct
- `scope` lists exactly what you asked for

If `tenant_id` is missing, you signed in as a user without the attribute (a common slip is staying signed in as the
realm admin). Sign out of the Keycloak account page, or use a private window, and try again.

Add `--print-token` to also print the token, to use with `curl`.

## Part 4: Practise the policy

Call the tools from Claude Desktop (Part 5) or from any MCP client. Run each scenario with the right user and scopes,
then compare with the expected result.

| # | Sign in as (scopes) | Ask for | Expected | Rule it shows |
|---|---|---|---|---|
| 1 | dr-ada (read scopes) | summary of `patient-400` | Allowed | Scope + purpose + assignment |
| 2 | dr-ada | roster | Only `patient-400` | Roster follows assignments |
| 3 | dr-ada | summary of `patient-500` | Denied | Revoked assignment |
| 4 | dr-ada | summary of `patient-600` | Denied, same message as #3 | Other tenant; no enumeration |
| 5 | dr-ada | summary of `patient-999` | Denied, same message again | A missing patient looks identical |
| 6 | dr-ada (read scopes only) | medications of `patient-500`, purpose `EMERGENCY` | Denied | No `patient.break_glass` scope |
| 7 | dr-ada (with break-glass) | same, with a justification | Allowed | Break-glass skips the assignment |
| 8 | dr-ada (with break-glass) | **notes** of `patient-500`, `EMERGENCY` | Denied | Emergency never opens free text |
| 9 | dr-ada (with break-glass) | `EMERGENCY` with no justification | Denied | Justification required (15–500 chars) |
| 10 | dr-ada (with break-glass) | `patient-600`, `EMERGENCY` | Denied | Break-glass never crosses hospitals |
| 11 | dr-ben | roster | `patient-400` and `patient-500` | Different user, different data |
| 12 | dr-cara | roster, then `patient-400` | Only `patient-600`; `patient-400` denied | Tenant isolation |
| 13 | dr-ada | access history | Denied | Clinicians don't hold `audit.read` |
| 14 | auditor-1 | access history of `patient-500`, break-glass events | Allowed; shows #6–#10 | The audit trail records everything |
| 15 | auditor-1 | summary of `patient-400` | Denied | Auditors are not clinicians |
| 16 | dr-ada, remove `medication.read` | medications of `patient-400` | Denied | One scope per data type |

Now look at what the database recorded. Every allowed **and** denied call has a row:

```sql
SELECT occurred_at, subject, patient_id, purpose, category, outcome, break_glass, left(justification, 30) AS why
FROM access_events ORDER BY occurred_at;
```

Then try the controls that sit under the application:

```sql
-- as the app's role, the audit table is append-only
\c patient_db_live healthcare_app
UPDATE access_events SET outcome = 'ALLOWED';     -- ERROR: permission denied
DELETE FROM access_events;                        -- ERROR: permission denied

-- row-level security: no tenant set means no rows
SELECT count(*) FROM patients;                    -- 0
BEGIN; SELECT set_config('app.tenant_id', 'hospital-B', true);
SELECT id FROM patients;                          -- patient-600 only
COMMIT;
```

And two token checks with `curl` (use `--print-token`):

```bash
# a token whose payload was edited (here, a different tenant) fails signature validation
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/mcp -H "Authorization: Bearer <edited token>"   # 401
# no token at all
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/mcp                                            # 401
```

> **Finding from a live run:** a plain bearer token (no DPoP proof) is **accepted**. DPoP support is present but not
> mandatory, so a stolen token can still be replayed within its lifetime. Making DPoP mandatory is an open item in
> the [README](../README.md#what-this-poc-leaves-out).

## Part 5: Talk to it from Claude Desktop

Claude Desktop's config file starts local programs, and its Connectors page needs a public HTTPS address, so neither
can point at `http://localhost:8080/mcp` directly. `mcp-remote` bridges the gap: Desktop starts it, it speaks HTTP to
the server, and it signs in through Keycloak using the OAuth metadata the server publishes.

Edit Claude Desktop's config (Settings → Developer → Edit Config) and add:

```json
{
  "mcpServers": {
    "healthcare-mcp": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote@0.14.3",
        "http://localhost:8080/mcp", "3334", "--allow-http",
        "--static-oauth-client-info", "{\"client_id\":\"healthcare-live-test\"}",
        "--static-oauth-client-metadata", "{\"scope\":\"openid patient.read medication.read notes.read patient.break_glass audit.read\"}"
      ]
    }
  }
}
```

- `3334` is the local callback port, and must match the redirect URI from step 1.3.
- `--allow-http` is needed because the server is on plain `http://localhost`. Never use it for a remote address.
- Pin the version, and check the release date before you bump it. This is third-party code that handles your token.
- The `scope` value is the **ceiling** for this session. To practise with a narrower token, remove scopes from it.

Quit Claude Desktop completely and reopen it. A browser tab opens on your Keycloak login; sign in as the user you
want to practise as. In a new chat you can then say things like:

- "List my patients."
- "Get the medications for patient-500."
- "Patient-500 is unconscious in the ER. Get their medications as an emergency. Justification: collapsed, unknown
  history."
- "Now get patient-500's clinical notes as an emergency." (refused, as in scenario 8)
- "Show recent break-glass events." (needs a token with `audit.read`)

To switch users, delete the cached login (`~/.mcp-auth`) and restart Desktop.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| App won't start: cannot reach the issuer | Wrong `OIDC_ISSUER`, or the deployment is stopped |
| Every call returns 401 | Missing `healthcare-mcp-server` audience (step 1.4), or a token older than 15 minutes (`JWT_MAX_LIFETIME`) |
| 401 and the log mentions the tenant | The `tenant_id` attribute or mapper is missing (steps 1.4, 1.5, 1.6) |
| Tools return "access denied" for everything | The user has no assignment row, or you used the wrong UUID (Part 2.3) |
| A scope you expect is missing from the token | It wasn't requested, or **Include in token scope** is off (step 1.2) |
| `invalid_scope` at sign-in | The scope exists but isn't attached to the client (step 1.3) |
| Device flow says `unauthorized_client` | **OAuth 2.0 Device Authorization Grant** is not ticked on the client |
| Redirect error from Keycloak in Desktop | The callback URI doesn't exactly match `http://localhost:3334/oauth/callback` |
| Desktop shows no tools | Quit it fully from the system tray; check the `healthcare-mcp` log under Settings → Developer |

## Clean up

- Stop the server, and drop the scratch database: `DROP DATABASE patient_db_live;`
- In Keycloak, delete the practice users, the `healthcare-live-test` client and the five scopes (or delete the whole
  deployment from the Cloud-IAM console).
- Remove the `healthcare-mcp` entry from Claude Desktop's config, and delete `~/.mcp-auth`.

## What this proves, and what it doesn't

It proves the tool policy, tenant isolation, break-glass rules and audit trail behave as documented **with tokens
from a real provider**, and that Claude Desktop can reach the server over HTTP with a normal OAuth login.

It does not prove: DPoP enforcement (it isn't enforced), mutual TLS against a real provider, behaviour under load, or
anything about a production deployment. The model provider behind Claude Desktop receives whatever a tool returns, so
this is another reason to keep to synthetic data.
