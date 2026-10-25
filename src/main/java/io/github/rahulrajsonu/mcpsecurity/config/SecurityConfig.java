package io.github.rahulrajsonu.mcpsecurity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.github.rahulrajsonu.mcpsecurity.security.CertificateBoundTokenFilter;
import io.github.rahulrajsonu.mcpsecurity.security.RateLimitFilter;
import io.github.rahulrajsonu.mcpsecurity.security.RateLimiter;
import io.github.rahulrajsonu.mcpsecurity.security.RequireHttpsFilter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
            String issuer,
            @Value("${app.public-url}")
            String publicUrl,
            Environment environment,
            @Value("${app.security.require-https:false}")
            boolean requireHttps,
            @Value("${app.mtls.enabled:false}")
            boolean mtlsEnabled,
            @Value("${app.mtls.require-certificate-bound-tokens:true}")
            boolean requireBoundTokens,
            RateLimiter rateLimiter) throws Exception {

        // Refuse floods before any token parsing. Per address first, then per token.
        http.addFilterBefore(new RateLimitFilter(rateLimiter), BearerTokenAuthenticationFilter.class);

        // With mutual TLS, tokens must be bound to the client certificate (RFC 8705).
        if (mtlsEnabled) {
            http.addFilterAfter(
                    new CertificateBoundTokenFilter(requireBoundTokens),
                    BearerTokenAuthenticationFilter.class);
        }

        // Health and metrics are only reachable on the separate management
        // port, never through the public listener.
        RequestMatcher onManagementPort = request -> {
            Integer managementPort = environment.getProperty("local.management.port", Integer.class);
            return managementPort != null && managementPort == request.getLocalPort();
        };
        // Refuse to serve PHI over plain HTTP, even if an ingress is misconfigured.
        // Behind a TLS-terminating proxy this relies on X-Forwarded-Proto.
        if (requireHttps) {
            http.addFilterBefore(
                    new RequireHttpsFilter(onManagementPort),
                    SecurityContextHolderFilter.class);
        }

        RequestMatcher actuator = RequestMatchers.allOf(
                PathPatternRequestMatcher.withDefaults().matcher("/actuator/health/**"),
                onManagementPort);
        RequestMatcher metrics = RequestMatchers.allOf(
                PathPatternRequestMatcher.withDefaults().matcher("/actuator/prometheus"),
                onManagementPort);

        return http
                // Stateless bearer/DPoP API: no cookies or sessions, so no CSRF surface.
                .csrf(csrf -> csrf.disable())

                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .headers(headers -> headers
                        .contentSecurityPolicy(csp ->
                                csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                        .frameOptions(frame -> frame.deny())
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(actuator, metrics)
                        .permitAll()

                        .requestMatchers("/mcp", "/mcp/**")
                        .authenticated()

                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/security/probe"
                        ).authenticated()

                        .anyRequest().denyAll()
                )

                .oauth2ResourceServer(oauth -> oauth
                        .jwt(Customizer.withDefaults())

                        .protectedResourceMetadata(metadata ->
                                metadata.protectedResourceMetadataCustomizer(
                                        builder -> builder
                                                .resource(publicUrl)
                                                .authorizationServer(issuer)
                                                .tlsClientCertificateBoundAccessTokens(mtlsEnabled)
                                )
                        )
                        .dPoP(Customizer.withDefaults())
                )

                .build();
    }
}
