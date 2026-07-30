package org.icpbrasil.signer.providers.vidaas;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.oauth.OAuth2Scope;
import org.icpbrasil.signer.providers.security.SecureTokenCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VidaasProviderTest {

    private TestCertificateFactory.TestCredentials credentials;
    private RecordingVidaasGateway apiClient;
    private VidaasProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        credentials = TestCertificateFactory.generateRsa2048();
        apiClient = new RecordingVidaasGateway();
        apiClient.certificates = List.of(new VidaasApiClient.VidaasCertificate(
                "CERT-VIDAAS:789",
                credentials.certificate()
        ));
        apiClient.rawSignature = new byte[]{3, 2, 1};

        provider = new VidaasProvider(
                Environment.HOMOLOGATION,
                apiClient,
                VidaasOAuth2Support.create(
                        Environment.HOMOLOGATION,
                        "client-id",
                        "client-secret",
                        HttpClientConfig.defaults()
                ),
                null,
                new SecureTokenCache<>(VidaasProvider.CERTIFICATE_CACHE_TTL)
        );
    }

    @Test
    void signHashDelegatesToApiWithSha256() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("pdf".getBytes());

        byte[] signature = provider.signHash(hash, "user-token");

        assertArrayEquals(new byte[]{3, 2, 1}, signature);
        assertEquals("user-token", apiClient.lastAccessToken);
        assertEquals("CERT-VIDAAS:789", apiClient.lastCertificateAlias);
        assertEquals(DigestAlgorithm.SHA256, apiClient.lastDigestAlgorithm);
    }

    @Test
    void getSignerCertificateUsesDiscoveryCache() {
        var first = provider.getSignerCertificate("user-token");
        var second = provider.getSignerCertificate("user-token");

        assertEquals(first, second);
        assertEquals(1, apiClient.discoveryCalls);
    }

    @Test
    void getProviderIdIsVidaas() {
        assertEquals("vidaas", provider.getProviderId());
    }

    @Test
    void rejectsMultipleCertificatesWithoutAlias() {
        apiClient.certificates = List.of(
                new VidaasApiClient.VidaasCertificate("A", credentials.certificate()),
                new VidaasApiClient.VidaasCertificate("B", credentials.certificate())
        );

        assertThrows(PscSigningException.class,
                () -> provider.getSignerCertificate("user-token"));
    }

    @Test
    void builderRejectsBlankClientSecret() {
        assertThrows(IllegalArgumentException.class, () -> new VidaasProviderBuilder()
                .withClientId("id")
                .withClientSecret(" ")
                .build());
    }

    @Test
    void oauth2BuildsPushAuthorizationUrl() {
        VidaasProvider built = (VidaasProvider) new VidaasProviderBuilder()
                .withClientId("id")
                .withClientSecret("secret")
                .build();

        var pkce = built.oauth2().generatePkceChallenge();
        String authUrl = built.oauth2().buildPushAuthorizationUrl(
                pkce,
                "12345678901",
                OAuth2Scope.SIGNATURE_SESSION,
                900
        );

        assertTrue(authUrl.contains("redirect_uri=push%3A%2F%2F"));
        assertTrue(authUrl.contains("login_hint=12345678901"));
    }

    private static final class RecordingVidaasGateway implements VidaasGateway {

        List<VidaasApiClient.VidaasCertificate> certificates = List.of();
        byte[] rawSignature = new byte[0];
        String lastAccessToken;
        String lastCertificateAlias;
        DigestAlgorithm lastDigestAlgorithm;
        int discoveryCalls;

        @Override
        public List<VidaasApiClient.VidaasCertificate> discoverCertificates(String accessToken) {
            discoveryCalls++;
            lastAccessToken = accessToken;
            return certificates;
        }

        @Override
        public byte[] signHash(
                String accessToken,
                String certificateAlias,
                byte[] documentHash,
                DigestAlgorithm digestAlgorithm) {
            lastAccessToken = accessToken;
            lastCertificateAlias = certificateAlias;
            lastDigestAlgorithm = digestAlgorithm;
            return rawSignature.clone();
        }
    }
}
