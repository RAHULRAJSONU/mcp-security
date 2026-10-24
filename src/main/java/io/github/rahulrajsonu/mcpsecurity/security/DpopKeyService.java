package io.github.rahulrajsonu.mcpsecurity.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

@Component
@Profile("oauth-demo")
public class DpopKeyService {

    private final ECKey key;

    public DpopKeyService() {
        try {
            this.key = new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException ex) {
            throw new IllegalStateException(
                    "Unable to generate DPoP key", ex);
        }
    }

    /**
     * Public-key thumbprint used as dpop_jkt in the
     * authorization request.
     */
    public String thumbprint() {
        try {
            return key.computeThumbprint("SHA-256").toString();
        } catch (JOSEException ex) {
            throw new IllegalStateException(
                    "Unable to compute DPoP key thumbprint", ex);
        }
    }

    /**
     * Creates a fresh proof for an HTTP request.
     * Pass null for accessToken at the token endpoint.
     */
    public String createProof(
            String method,
            URI requestUri,
            String accessToken,
            String nonce) {

        try {
            String htu = new URI(
                    requestUri.getScheme(),
                    requestUri.getAuthority(),
                    requestUri.getPath(),
                    null,
                    null
            ).toASCIIString();

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issueTime(Date.from(Instant.now()))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", method.toUpperCase(Locale.ROOT))
                    .claim("htu", htu);

            if (accessToken != null && !accessToken.isBlank()) {
                claims.claim("ath", accessTokenHash(accessToken));
            }

            if (nonce != null && !nonce.isBlank()) {
                claims.claim("nonce", nonce);
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(key.toPublicJWK())
                    .build();

            SignedJWT proof = new SignedJWT(header, claims.build());
            proof.sign(new ECDSASigner(key));

            return proof.serialize();

        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Unable to create DPoP proof", ex);
        }
    }

    private String accessTokenHash(String accessToken)
            throws java.security.NoSuchAlgorithmException {

        byte[] hash = java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(accessToken.getBytes(
                        java.nio.charset.StandardCharsets.US_ASCII));

        return java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(hash);
    }
}