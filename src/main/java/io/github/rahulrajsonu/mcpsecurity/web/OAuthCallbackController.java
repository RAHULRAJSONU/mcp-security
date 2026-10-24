package io.github.rahulrajsonu.mcpsecurity.web;

import com.nimbusds.jwt.SignedJWT;
import io.github.rahulrajsonu.mcpsecurity.filter.PkceUtils;
import io.github.rahulrajsonu.mcpsecurity.security.DpopKeyService;
import io.github.rahulrajsonu.mcpsecurity.security.OAuthTransactionStore;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Map;

@RestController
@Profile("oauth-demo")
public class OAuthCallbackController {

    private final OAuthTransactionStore transactions;
    private final JwtDecoder idTokenDecoder;
    private final DpopKeyService dpopKeyService;
    private final RestClient restClient;

    private final String issuer;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String publicUrl;

    public OAuthCallbackController(
            OAuthTransactionStore transactions,
            DpopKeyService dpopKeyService,
            @Qualifier("idTokenDecoder") JwtDecoder idTokenDecoder,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer,
            @Value("${app.oauth.client-id}") String clientId,
            @Value("${app.oauth.client-secret}") String clientSecret,
            @Value("${app.oauth.redirect-uri}") String redirectUri,
            @Value("${app.public-url}") String publicUrl) {

        this.transactions = transactions;
        this.dpopKeyService = dpopKeyService;
        this.idTokenDecoder = idTokenDecoder;
        this.issuer = issuer;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.publicUrl = publicUrl;
        this.restClient = RestClient.create();
    }

    @GetMapping("/oauth/login")
    public void login(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        HttpSession session = request.getSession(true);

        String verifier = PkceUtils.generateCodeVerifier();
        String challenge = PkceUtils.generateCodeChallenge(verifier);
        String state = PkceUtils.generateCodeVerifier();
        String nonce = PkceUtils.generateCodeVerifier();
        String dpopJkt = dpopKeyService.thumbprint();

        transactions.save(
                session,
                new OAuthTransactionStore.Transaction(
                        state, nonce, verifier));

        String authorizationUrl = issuer
                + "/protocol/openid-connect/auth"
                + "?response_type=code"
                + "&client_id=" + enc(clientId)
                + "&redirect_uri=" + enc(redirectUri)
                + "&scope=" + enc("openid profile")
                + "&state=" + enc(state)
                + "&nonce=" + enc(nonce)
                + "&code_challenge=" + enc(challenge)
                + "&code_challenge_method=S256"
                + "&dpop_jkt=" + enc(dpopJkt);

        response.sendRedirect(authorizationUrl);
    }

    @GetMapping("/oauth/callback")
    public String callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            HttpServletRequest request) {

        if (error != null) {
            throw new IllegalArgumentException(
                    "Identity provider returned an authorization error");
        }

        if (code == null || code.isBlank()
                || state == null || state.isBlank()) {
            throw new IllegalArgumentException(
                    "Missing authorization code or state");
        }

        HttpSession session = request.getSession(false);

        if (session == null) {
            throw new IllegalArgumentException(
                    "Login session is missing");
        }

        OAuthTransactionStore.Transaction tx =
                transactions.consume(session);

        if (!constantTimeEquals(tx.state(), state)) {
            throw new IllegalArgumentException("Invalid OAuth state");
        }

        MultiValueMap<String, String> form =
                new LinkedMultiValueMap<>();

        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        if (!clientSecret.isBlank()) {
            form.add("client_secret", clientSecret);
        }
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("code_verifier", tx.verifier());

        URI tokenEndpoint = URI.create(
                issuer + "/protocol/openid-connect/token");

        String dpopProof = dpopKeyService.createProof(
                "POST",
                tokenEndpoint,
                null,
                null);

        Map<?, ?> tokenResponse = exchangeCodeForTokens(tokenEndpoint, form);

        if (tokenResponse == null) {
            throw new IllegalStateException(
                    "Identity provider returned an empty token response");
        }

        if (!"DPoP".equalsIgnoreCase(
                String.valueOf(tokenResponse.get("token_type")))) {
            throw new IllegalStateException(
                    "Identity provider did not return a DPoP token");
        }
        Object accessTokenValue = tokenResponse.get("access_token");

        if (!(accessTokenValue instanceof String accessToken)
                || accessToken.isBlank()) {
            throw new IllegalStateException(
                    "Token response did not contain an access token");
        }

        Object idTokenValue = tokenResponse.get("id_token");

        if (!(idTokenValue instanceof String idToken)
                || idToken.isBlank()) {
            throw new IllegalStateException(
                    "Token response did not contain an ID token");
        }

        Jwt validatedIdToken = idTokenDecoder.decode(idToken);

        String returnedNonce =
                validatedIdToken.getClaimAsString("nonce");

        if (!constantTimeEquals(tx.nonce(), returnedNonce)) {
            throw new IllegalArgumentException(
                    "Invalid ID token nonce");
        }

        verifyDpopBinding(accessToken);
        probe(accessTokenValue.toString());

        // Do not return access tokens, ID tokens, or DPoP proofs
        // to the browser.
        return "Login successful for subject: "
                + validatedIdToken.getSubject();
    }

    private static boolean constantTimeEquals(
            String expected,
            String actual) {

        if (expected == null || actual == null) {
            return false;
        }

        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private Map<?, ?> exchangeCodeForTokens(
            URI tokenEndpoint,
            MultiValueMap<String, String> form) {

        String nonce = null;

        for (int attempt = 0; attempt < 2; attempt++) {
            String proof = dpopKeyService.createProof(
                    "POST", tokenEndpoint, null, nonce);

            var response = restClient.post()
                    .uri(tokenEndpoint)
                    .header("DPoP", proof)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, clientResponse) -> {
                        int status = clientResponse.getStatusCode().value();
                        String responseNonce = clientResponse.getHeaders()
                                .getFirst("DPoP-Nonce");

                        Map<?, ?> body = clientResponse.bodyTo(Map.class);

                        return new TokenExchangeResponse(
                                status, responseNonce, body);
                    });

            if (response.status() >= 200 && response.status() < 300) {
                return response.body();
            }

            if (attempt == 0
                    && response.nonce() != null
                    && !response.nonce().isBlank()) {
                nonce = response.nonce();
                continue;
            }

            throw new IllegalStateException(
                    "Token exchange failed with HTTP status "
                            + response.status());
        }

        throw new IllegalStateException(
                "Token exchange failed after DPoP nonce retry");
    }

    private record TokenExchangeResponse(
            int status,
            String nonce,
            Map<?, ?> body) {}

    private void verifyDpopBinding(String accessToken) {
        try {
            // Diagnostic parsing only. This does NOT verify the JWT signature.
            SignedJWT parsed = SignedJWT.parse(accessToken);

            Map<String, Object> claims =
                    parsed.getJWTClaimsSet().getClaims();

            Object cnfValue = claims.get("cnf");

            if (!(cnfValue instanceof Map<?, ?> cnf)) {
                throw new IllegalStateException(
                        "Access token has no DPoP confirmation claim");
            }

            Object jktValue = cnf.get("jkt");

            if (!(jktValue instanceof String tokenThumbprint)) {
                throw new IllegalStateException(
                        "Access token has no cnf.jkt thumbprint");
            }

            String expectedThumbprint = dpopKeyService.thumbprint();

            if (!MessageDigest.isEqual(
                    expectedThumbprint.getBytes(StandardCharsets.UTF_8),
                    tokenThumbprint.getBytes(StandardCharsets.UTF_8))) {
                throw new IllegalStateException(
                        "Access token is bound to a different DPoP key");
            }

        } catch (ParseException ex) {
            throw new IllegalStateException(
                    "Access token is not a parseable JWT", ex);
        }
    }

    private void probe(String accessToken){
        URI apiUri = URI.create(publicUrl + "/api/security/probe");

        String proof = dpopKeyService.createProof(
                "GET",
                apiUri,
                accessToken,
                null);

        var response = restClient.get()
                .uri(apiUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", proof)
                .retrieve()
                .toEntity(String.class);
    }

}