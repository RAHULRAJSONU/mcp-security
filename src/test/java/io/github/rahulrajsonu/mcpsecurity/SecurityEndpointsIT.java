package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SecurityEndpointsIT extends AbstractPostgresIT {

    @Value("${local.server.port}")
    int port;

    @Value("${local.management.port}")
    int managementPort;

    private final HttpClient client = HttpClient.newHttpClient();

    private HttpResponse<String> get(String path) throws Exception {
        return get(port, path);
    }

    private HttpResponse<String> get(int onPort, String path) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + onPort + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void mcpEndpointRequiresAuthentication() throws Exception {
        assertThat(get("/mcp").statusCode()).isEqualTo(401);
    }

    @Test
    void healthAndMetricsAreServedOnlyOnTheManagementPort() throws Exception {
        assertThat(get(managementPort, "/actuator/health/readiness").statusCode()).isEqualTo(200);
        assertThat(get(managementPort, "/actuator/prometheus").body()).contains("jvm_memory_used_bytes");

        assertThat(get("/actuator/health").statusCode()).isNotEqualTo(200);
        assertThat(get("/actuator/prometheus").statusCode()).isNotEqualTo(200);
    }

    @Test
    void everythingElseIsRejected() throws Exception {
        for (String path : new String[] {"/actuator/env", "/swagger-ui/index.html", "/oauth/login", "/"}) {
            assertThat(get(path).statusCode())
                    .as(path)
                    .isIn(401, 403, 404);
        }
    }

    @Test
    void protectedResourceMetadataAdvertisesConfiguredPublicUrl() throws Exception {
        HttpResponse<String> response = get("/.well-known/oauth-protected-resource");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("http://localhost:8080");
    }

    @Test
    void responsesCarryHardenedHeaders() throws Exception {
        HttpResponse<String> response = get("/mcp");

        assertThat(response.headers().firstValue("X-Content-Type-Options")).hasValue("nosniff");
        assertThat(response.headers().firstValue("Content-Security-Policy")).isPresent();
    }

    @Test
    void responsesAreNeverCacheable() throws Exception {
        // Intermediaries and browsers must not keep copies of anything that could hold PHI.
        assertThat(get("/mcp").headers().firstValue("Cache-Control").orElse(""))
                .contains("no-store");
    }
}
