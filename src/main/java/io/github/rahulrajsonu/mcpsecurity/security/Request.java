package io.github.rahulrajsonu.mcpsecurity.security;

public record Request(
        String authorizationUrl,
        String codeVerifier,
        String state,
        String nonce) {
}