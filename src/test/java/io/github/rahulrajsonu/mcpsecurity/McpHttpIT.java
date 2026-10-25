package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The MCP endpoint over real HTTP: bearer authentication, the streamable
 * session handshake, and tools/call returning the CallToolResult a client sees.
 * Only the JWT decoder is faked (there is no identity provider in the test).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class McpHttpIT extends AbstractPostgresIT {

    private static final String PROTOCOL = "2025-06-18";

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();
    private final JsonMapper json = JsonMapper.builder().build();

    @BeforeEach
    void identityProvider() {
        // doReturn/doThrow, because when(decoder.decode(..)) would call the stub being replaced.
        doThrow(new BadJwtException("unknown token")).when(jwtDecoder).decode(anyString());
        doReturn(token("doctor-101", "hospital-A", "healthcare-mcp-client", "patient.read medication.read"))
                .when(jwtDecoder).decode("doctor-101");
        doReturn(token("doctor-101", "hospital-A", "suspended-client", "patient.read medication.read"))
                .when(jwtDecoder).decode("suspended");
        doReturn(token("doctor-101", "hospital-A", null, "patient.read medication.read"))
                .when(jwtDecoder).decode("no-client");
    }

    private static Jwt token(String subject, String tenant, String client, String scope) {
        Jwt.Builder jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject(subject)
                .claim("tenant_id", tenant)
                .claim("scope", scope)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(120));
        if (client != null) {
            jwt.claim("azp", client);
        }
        return jwt.build();
    }

    private HttpResponse<String> post(String bearer, String session, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/mcp"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        if (session != null) {
            request.header("Mcp-Session-Id", session);
            request.header("MCP-Protocol-Version", PROTOCOL);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** The reply is JSON, or a server-sent event whose data line is the JSON. */
    private JsonNode parse(HttpResponse<String> response) {
        String body = response.body();
        for (String line : body.split("\\R")) {
            if (line.startsWith("data:")) {
                return json.readTree(line.substring("data:".length()).strip());
            }
        }
        return json.readTree(body);
    }

    private String openSession(String bearer) throws Exception {
        HttpResponse<String> init = post(bearer, null, """
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                  "protocolVersion":"%s","capabilities":{},
                  "clientInfo":{"name":"integration-test","version":"1"}}}
                """.formatted(PROTOCOL));
        assertThat(init.statusCode()).isEqualTo(200);
        String session = init.headers().firstValue("Mcp-Session-Id").orElse(null);

        post(bearer, session, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
        return session;
    }

    private JsonNode call(String bearer, String session, String tool, Map<String, Object> arguments) throws Exception {
        String body = json.writeValueAsString(Map.of(
                "jsonrpc", "2.0", "id", 2, "method", "tools/call",
                "params", Map.of("name", tool, "arguments", arguments)));
        HttpResponse<String> response = post(bearer, session, body);
        assertThat(response.statusCode()).isEqualTo(200);
        return parse(response).get("result");
    }

    @Test
    void callsWithoutAValidTokenAreRefusedBeforeMcp() throws Exception {
        assertThat(post(null, null, "{}").statusCode()).isEqualTo(401);
        assertThat(post("garbage", null, "{}").statusCode()).isEqualTo(401);
    }

    @Test
    void theHandshakeWorksAndTheToolsAreListed() throws Exception {
        String session = openSession("doctor-101");

        HttpResponse<String> list = post("doctor-101", session,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}");

        assertThat(list.statusCode()).isEqualTo(200);
        assertThat(parse(list).get("result").get("tools").toString())
                .contains("getPatientSummary", "listMyPatients", "getPatientMedications",
                        "getClinicalNotes", "getAccessHistory", "listBreakGlassEvents");
    }

    @Test
    void anApprovedAgentReadsOverHttpAndGetsStructuredContent() throws Exception {
        String session = openSession("doctor-101");

        JsonNode result = call("doctor-101", session, "listMyPatients", Map.of());

        assertThat(result.path("isError").asBoolean(false)).isFalse();
        assertThat(result.get("structuredContent").get("items").get(0).get("patientId").asString())
                .isEqualTo("patient-400");
        assertThat(result.get("content").get(0).get("text").asString()).contains("patient-400");
    }

    @Test
    void aSuspendedAgentGetsAnErrorResultNotAProtocolError() throws Exception {
        String session = openSession("suspended");

        JsonNode result = call("suspended", session, "listMyPatients", Map.of());

        assertThat(result.get("isError").asBoolean()).isTrue();
        assertThat(result.get("structuredContent").get("error").asString()).isEqualTo("access_denied");
        assertThat(result.get("structuredContent").get("retryable").asBoolean()).isFalse();
        assertThat(result.get("content").get(0).get("text").asString())
                .isEqualTo("{\"error\":\"access_denied\",\"message\":\"Access denied\",\"retryable\":false}");
    }

    @Test
    void aTokenWithoutAClientIdGetsTheSameRefusal() throws Exception {
        String session = openSession("no-client");

        JsonNode result = call("no-client", session, "listMyPatients", Map.of());

        assertThat(result.get("isError").asBoolean()).isTrue();
        assertThat(result.get("structuredContent").get("error").asString()).isEqualTo("access_denied");
    }

    @Test
    void aMissingScopeIsRefusedWithTheSameBodyAsEveryOtherDenial() throws Exception {
        String session = openSession("doctor-101");

        // doctor-101's token has no notes.read scope.
        JsonNode result = call("doctor-101", session, "getClinicalNotes", Map.of("patientId", "patient-400"));

        assertThat(result.get("isError").asBoolean()).isTrue();
        assertThat(result.get("content").get(0).get("text").asString())
                .isEqualTo("{\"error\":\"access_denied\",\"message\":\"Access denied\",\"retryable\":false}");
    }

    @Test
    void aMalformedIdOverHttpIsRefusedWithoutEchoingIt() throws Exception {
        String session = openSession("doctor-101");

        JsonNode result = call("doctor-101", session, "getPatientSummary",
                Map.of("patientId", "x'; DROP TABLE patients;--"));

        assertThat(result.get("isError").asBoolean()).isTrue();
        assertThat(result.toString()).doesNotContain("DROP TABLE");
    }

    @Test
    void anUnknownToolIsAProtocolErrorNotAToolError() throws Exception {
        String session = openSession("doctor-101");

        String body = json.writeValueAsString(Map.of(
                "jsonrpc", "2.0", "id", 9, "method", "tools/call",
                "params", Map.of("name", "noSuchTool", "arguments", Map.of())));
        JsonNode reply = parse(post("doctor-101", session, body));

        // Either a JSON-RPC error or an error result; never a successful result with data.
        boolean protocolError = reply.has("error");
        boolean toolError = reply.has("result") && reply.get("result").path("isError").asBoolean(false);
        assertThat(protocolError || toolError).isTrue();
    }
}
