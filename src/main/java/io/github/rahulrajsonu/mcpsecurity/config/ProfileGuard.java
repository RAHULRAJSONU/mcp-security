package io.github.rahulrajsonu.mcpsecurity.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

/** The developer profiles weaken security on purpose, so they must never start beside prod. */
@Configuration
@RequiredArgsConstructor
public class ProfileGuard {

    private final Environment environment;

    @PostConstruct
    void refuseDeveloperProfilesInProd() {
        if (environment.acceptsProfiles(Profiles.of("prod"))
                && environment.acceptsProfiles(Profiles.of("local", "oauth-demo"))) {
            throw new IllegalStateException(
                    "The local and oauth-demo profiles must not be active together with prod");
        }
    }
}
