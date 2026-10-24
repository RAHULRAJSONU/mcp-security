#!/usr/bin/env node
// Signs in with the OAuth 2.0 device authorization grant and prints the token's claims.
// You sign in in your own browser; no password passes through this script.
//
//   OIDC_ISSUER=https://<host>/auth/realms/<realm> node scripts/device-login.js [--print-token]
//
// Optional: OIDC_CLIENT_ID (default healthcare-live-test), SCOPES (space separated).
// Requires Node 18+ (global fetch).

const ISSUER = (process.env.OIDC_ISSUER || '').replace(/\/$/, '');
const CLIENT_ID = process.env.OIDC_CLIENT_ID || 'healthcare-live-test';
const SCOPES = process.env.SCOPES || 'openid patient.read medication.read notes.read';

if (!ISSUER) {
  console.error('Set OIDC_ISSUER, for example https://lemur-1.cloud-iam.com/auth/realms/my-realm');
  process.exit(1);
}

const post = async (url, body) => {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });
  return { status: response.status, json: await response.json() };
};

(async () => {
  const base = `${ISSUER}/protocol/openid-connect`;
  const start = await post(`${base}/auth/device`, { client_id: CLIENT_ID, scope: SCOPES });
  if (start.status !== 200) {
    console.error('Could not start the device flow:', start.json);
    process.exit(1);
  }

  console.log(`\nOpen:  ${start.json.verification_uri_complete}`);
  console.log(`Code:  ${start.json.user_code}   (valid for ${start.json.expires_in}s)\n`);

  const deadline = Date.now() + start.json.expires_in * 1000;
  let delay = (start.json.interval || 5) * 1000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, delay));
    const poll = await post(`${base}/token`, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: start.json.device_code,
      client_id: CLIENT_ID,
    });
    if (poll.status === 200) {
      const token = poll.json.access_token;
      const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      console.log('Signed in. The claims the server will see:');
      console.log(JSON.stringify({
        sub: claims.sub,
        aud: claims.aud,
        tenant_id: claims.tenant_id,
        scope: claims.scope,
        lifetime_seconds: claims.exp - claims.iat,
      }, null, 2));
      if (process.argv.includes('--print-token')) {
        console.log(`\n${token}`);
      }
      return;
    }
    if (poll.json.error === 'slow_down') {
      delay += 5000;
    } else if (poll.json.error !== 'authorization_pending') {
      console.error('Sign-in failed:', poll.json);
      process.exit(1);
    }
  }
  console.error('The code expired before sign-in finished. Run the script again.');
  process.exit(1);
})();
