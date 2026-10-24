package io.github.rahulrajsonu.mcpsecurity.security;

import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("oauth-demo")
public class OAuthTransactionStore {
    private static final String STATE = "oauth.state";
    private static final String NONCE = "oauth.nonce";
    private static final String VERIFIER = "oauth.verifier";

    public record Transaction(String state, String nonce, String verifier) {}

    public void save(HttpSession session, Transaction tx) {
        session.setAttribute(STATE, tx.state());
        session.setAttribute(NONCE, tx.nonce());
        session.setAttribute(VERIFIER, tx.verifier());
    }

    public Transaction consume(HttpSession session) {
        String state = (String) session.getAttribute(STATE);
        String nonce = (String) session.getAttribute(NONCE);
        String verifier = (String) session.getAttribute(VERIFIER);

        // Remove first, so a callback cannot reuse the transaction.
        session.removeAttribute(STATE);
        session.removeAttribute(NONCE);
        session.removeAttribute(VERIFIER);

        if (state == null || nonce == null || verifier == null) {
            throw new IllegalStateException(
                    "Missing or already consumed OAuth transaction");
        }

        return new Transaction(state, nonce, verifier);
    }
}