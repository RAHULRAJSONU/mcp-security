package io.github.rahulrajsonu.mcpsecurity.security;

import io.github.rahulrajsonu.mcpsecurity.filter.PkceUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class PkceAuthorizationRequest {

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();
    private static final String clientId = "healthcare-mcp-client";
    private static final String callbackUrl = "http://127.0.0.1:8085/callback";

    private PkceAuthorizationRequest() {
    }

    public record Request(String authorizationUrl,
                          String codeVerifier,
                          String state) {
    }

    public static Request create(
            String authorizationEndpoint,
            String clientId,
            String redirectUri,
            String scope) {

        String verifier = PkceUtils.generateCodeVerifier();
        String challenge = PkceUtils.generateCodeChallenge(verifier);
        String state = PkceUtils.generateCodeVerifier();

        String url = authorizationEndpoint
                + "?response_type=code"
                + "&client_id=" + encode(clientId)
                + "&redirect_uri=" + encode(redirectUri)
                + "&scope=" + encode(scope)
                + "&state=" + encode(state)
                + "&code_challenge=" + encode(challenge)
                + "&code_challenge_method=S256";

        return new Request(url, verifier, state);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}