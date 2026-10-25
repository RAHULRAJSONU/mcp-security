package io.github.rahulrajsonu.mcpsecurity.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

class AgentControlPropertiesTest {

    @Configuration
    @EnableConfigurationProperties({AgentControlProperties.class, BreakGlassProperties.class})
    static class Binding {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Binding.class);

    @Test
    void defaultsAreTheDocumentedOnes() {
        runner.run(context -> {
            AgentControlProperties props = context.getBean(AgentControlProperties.class);
            assertThat(props.callsPerMinute()).isEqualTo(120);
            assertThat(props.callsPerDay()).isEqualTo(5000);
            assertThat(props.registryCacheTtl()).isEqualTo(Duration.ofSeconds(5));
            assertThat(context.getBean(BreakGlassProperties.class).stepUpRequired()).isFalse();
        });
    }

    @Test
    void valuesBindFromConfiguration() {
        runner.withPropertyValues(
                        "app.security.agent.calls-per-minute=7",
                        "app.security.agent.calls-per-day=70",
                        "app.security.agent.registry-cache-ttl=PT30S",
                        "app.security.break-glass.required-acr=urn:x")
                .run(context -> {
                    AgentControlProperties props = context.getBean(AgentControlProperties.class);
                    assertThat(props.callsPerMinute()).isEqualTo(7);
                    assertThat(props.callsPerDay()).isEqualTo(70);
                    assertThat(props.registryCacheTtl()).isEqualTo(Duration.ofSeconds(30));
                    assertThat(context.getBean(BreakGlassProperties.class).requiredAcr()).isEqualTo("urn:x");
                });
    }

    @Test
    void aNegativeCacheTimeIsRefusedAtStartup() {
        runner.withPropertyValues("app.security.agent.registry-cache-ttl=-PT1S")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void stepUpIsRequiredOnlyWhenAnAcrIsConfigured() {
        assertThat(new BreakGlassProperties("").stepUpRequired()).isFalse();
        assertThat(new BreakGlassProperties("  ").stepUpRequired()).isFalse();
        assertThat(new BreakGlassProperties(null).stepUpRequired()).isFalse();
        assertThat(new BreakGlassProperties("urn:x").stepUpRequired()).isTrue();
    }

    @Test
    void zeroCacheTimeIsAllowedAndMeansNoReuse() {
        assertThatCode(() -> new AgentControlProperties(1, 1, 1, Duration.ZERO)).doesNotThrowAnyException();
        assertThatThrownBy(() -> new AgentControlProperties(1, 1, 1, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
