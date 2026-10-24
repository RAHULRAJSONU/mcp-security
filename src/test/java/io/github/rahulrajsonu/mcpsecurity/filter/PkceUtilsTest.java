package io.github.rahulrajsonu.mcpsecurity.filter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PkceUtilsTest {

    @Test
    void verifierHasValidLength() {
        String verifier = PkceUtils.generateCodeVerifier();

        assertTrue(verifier.length() >= 43);
        assertTrue(verifier.length() <= 128);
    }

    @Test
    void challengeIsDeterministicForSameVerifier() {
        String verifier = PkceUtils.generateCodeVerifier();

        String first =
                PkceUtils.generateCodeChallenge(verifier);
        String second =
                PkceUtils.generateCodeChallenge(verifier);

        assertEquals(first, second);
    }

    @Test
    void differentVerifiersProduceDifferentChallenges() {
        String firstVerifier = PkceUtils.generateCodeVerifier();
        String secondVerifier = PkceUtils.generateCodeVerifier();

        assertNotEquals(
                PkceUtils.generateCodeChallenge(firstVerifier),
                PkceUtils.generateCodeChallenge(secondVerifier));
    }

    @Test
    void rejectsBlankVerifier() {
        assertThrows(
                IllegalArgumentException.class,
                () -> PkceUtils.generateCodeChallenge(" "));
    }
}