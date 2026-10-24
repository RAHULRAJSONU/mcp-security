package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * With app.security.require-https on (the prod profile), the service refuses
 * to answer over plain HTTP, so a misconfigured ingress cannot serve PHI in
 * the clear. Behind a TLS-terminating proxy the scheme comes from
 * X-Forwarded-Proto, which the proxy must set itself.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "app.security.require-https=true")
class HttpsEnforcementIT extends AbstractPostgresIT {

    @Value("${local.server.port}")
    int port;

    @Value("${local.management.port}")
    int managementPort;

    private final HttpClient client = HttpClient.newHttpClient();

    private HttpResponse<String> get(int onPort, String path, String... headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + onPort + path)).GET();
        if (headers.length > 0) {
            request.headers(headers);
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void plainHttpIsRefusedAndNeverServed() throws Exception {
        HttpResponse<String> response = get(port, "/mcp");

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).isEmpty();
    }

    @Test
    void publicDiscoveryIsNotServedOverPlainHttp() throws Exception {
        assertThat(get(port, "/.well-known/oauth-protected-resource").statusCode()).isEqualTo(403);
    }

    @Test
    void requestsArrivingThroughATlsProxyAreServedNormally() throws Exception {
        HttpResponse<String> response = get(port, "/mcp", "X-Forwarded-Proto", "https");

        // Reached the application, which then demands a token.
        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    void theInternalManagementPortKeepsWorkingForProbes() throws Exception {
        assertThat(get(managementPort, "/actuator/health/readiness").statusCode()).isEqualTo(200);
    }
}
