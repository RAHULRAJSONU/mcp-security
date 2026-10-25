package io.github.rahulrajsonu.mcpsecurity.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class ProfileGuardTest {

    private static ProfileGuard guard(String... profiles) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(profiles);
        return new ProfileGuard(env);
    }

    @Test
    void developerProfilesAreRefusedBesideProd() {
        assertThatThrownBy(() -> guard("prod", "local").refuseDeveloperProfilesInProd())
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> guard("prod", "oauth-demo").refuseDeveloperProfilesInProd())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void eachProfileIsFineOnItsOwn() {
        assertThatCode(() -> guard("prod").refuseDeveloperProfilesInProd()).doesNotThrowAnyException();
        assertThatCode(() -> guard("local", "oauth-demo").refuseDeveloperProfilesInProd()).doesNotThrowAnyException();
    }
}
