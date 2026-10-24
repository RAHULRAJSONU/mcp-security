package io.github.rahulrajsonu.mcpsecurity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * A real TLS handshake with client-certificate authentication. Certificates are
 * generated with the JDK's keytool, so nothing sensitive is committed.
 * Reaching HTTP 401 proves the handshake passed and the application then
 * demanded a token; a handshake failure surfaces as an IOException.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test", "mtls"})
class MutualTlsIT extends AbstractPostgresIT {

    private static final String PASSWORD = "changeit";
    private static final Path DIR = generateCertificates();

    @Value("${local.server.port}")
    int port;

    @DynamicPropertySource
    static void tls(DynamicPropertyRegistry registry) {
        registry.add("MTLS_KEYSTORE", () -> "file:" + DIR.resolve("server.p12"));
        registry.add("MTLS_KEYSTORE_PASSWORD", () -> PASSWORD);
        registry.add("MTLS_TRUSTSTORE", () -> "file:" + DIR.resolve("server-trust.p12"));
        registry.add("MTLS_TRUSTSTORE_PASSWORD", () -> PASSWORD);
    }

    private HttpResponse<String> get(HttpClient client, String path) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void clientWithoutCertificateCannotConnect() throws Exception {
        HttpClient client = client(null);

        assertThatThrownBy(() -> get(client, "/.well-known/oauth-protected-resource"))
                .isInstanceOf(IOException.class);
    }

    @Test
    void clientWithCertificateTheServerDoesNotTrustCannotConnect() throws Exception {
        HttpClient client = client("rogue.p12");

        assertThatThrownBy(() -> get(client, "/.well-known/oauth-protected-resource"))
                .isInstanceOf(IOException.class);
    }

    @Test
    void trustedClientReachesTheApplicationWhichStillDemandsAToken() throws Exception {
        HttpClient client = client("client.p12");

        assertThat(get(client, "/mcp").statusCode()).isEqualTo(401);
    }

    @Test
    void metadataAdvertisesCertificateBoundTokens() throws Exception {
        HttpClient client = client("client.p12");

        HttpResponse<String> response = get(client, "/.well-known/oauth-protected-resource");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"tls_client_certificate_bound_access_tokens\":true");
    }

    // ---- helpers ----

    private static HttpClient client(String clientKeystore) throws Exception {
        KeyManagerFactory keys = null;

        if (clientKeystore != null) {
            keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(load(DIR.resolve(clientKeystore)), PASSWORD.toCharArray());
        }

        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(load(DIR.resolve("client-trust.p12")));

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys == null ? null : keys.getKeyManagers(), trust.getTrustManagers(), null);

        return HttpClient.newBuilder().sslContext(context).build();
    }

    private static KeyStore load(Path path) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(path)) {
            store.load(in, PASSWORD.toCharArray());
        }
        return store;
    }

    private static Path generateCertificates() {
        try {
            Path dir = Files.createTempDirectory("mtls-it");
            dir.toFile().deleteOnExit();

            keypair(dir, "server", "CN=localhost", "san=dns:localhost,ip:127.0.0.1");
            keypair(dir, "client", "CN=test-client", null);
            keypair(dir, "rogue", "CN=untrusted-client", null);

            // The server trusts only "client"; the client trusts only "server".
            trust(dir, "client", "server-trust");
            trust(dir, "server", "client-trust");
            return dir;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate test certificates", ex);
        }
    }

    private static void keypair(Path dir, String name, String dn, String san) throws Exception {
        List<String> command = new java.util.ArrayList<>(List.of(
                "-genkeypair", "-alias", name, "-keyalg", "RSA", "-keysize", "2048",
                "-dname", dn, "-validity", "2", "-storetype", "PKCS12",
                "-keystore", dir.resolve(name + ".p12").toString(), "-storepass", PASSWORD));
        if (san != null) {
            command.addAll(List.of("-ext", san));
        }
        keytool(command);
    }

    private static void trust(Path dir, String certificateOwner, String truststoreName) throws Exception {
        Path certificate = dir.resolve(certificateOwner + ".cer");
        keytool(List.of("-exportcert", "-alias", certificateOwner,
                "-keystore", dir.resolve(certificateOwner + ".p12").toString(),
                "-storepass", PASSWORD, "-file", certificate.toString()));
        keytool(List.of("-importcert", "-noprompt", "-alias", certificateOwner,
                "-file", certificate.toString(), "-storetype", "PKCS12",
                "-keystore", dir.resolve(truststoreName + ".p12").toString(), "-storepass", PASSWORD));
    }

    private static void keytool(List<String> arguments) throws Exception {
        String executable = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "keytool.exe" : "keytool").toString();

        List<String> command = new java.util.ArrayList<>();
        command.add(executable);
        command.addAll(arguments);

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());

        if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
    }
}
