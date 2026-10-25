package io.github.rahulrajsonu.mcpsecurity.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({AgentControlProperties.class, BreakGlassProperties.class})
public class AgentControlConfig {
}
