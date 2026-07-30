package org.icpbrasil.signer.providers.remoteid;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.security.SecureTokenCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteIdProviderTest {

    private static final String API_BASE = "https://api-hom.example.certisign/remoteid";

    private TestCertificateFactory.TestCredentials credentials;
    private RecordingRemoteIdGateway apiClient;
    private RemoteIdProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        credentials = TestCertificateFactory.generateRsa2048();
        apiClient = new RecordingRemoteIdGateway();
        apiClient.certificates = List.of(new RemoteIdApiClient.RemoteIdCertificate(
                "CERT-REMOTE:456",
                credentials.certificate()
        ));
        apiClient.rawSignature = new byte[]{5, 6, 7, 8};

        provider = new RemoteIdProvider(
                Environment.HOMOLOGATION,
                API_BASE,
                apiClient,
                RemoteIdOAuth2Support.create(
                        API_BASE,
                        "client-id",
                        "client-secret",
                        HttpClientConfig.defaults()
                ),
                null,
                new SecureTokenCache<>(RemoteIdProvider.CERTIFICATE_CACHE_TTL)
        );
    }

    @Test
    void signHashDelegatesToApiWithSha256() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("pdf".getBytes());

        byte[] signature = provider.signHash(hash, "user-token");

        assertArrayEquals(new byte[]{5, 6, 7, 8}, signature);
        assertEquals("user-token", apiClient.lastAccessToken);
        assertEquals("CERT-REMOTE:456", apiClient.lastCertificateAlias);
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
    void getProviderIdIsRemoteId() {
        assertEquals("remoteid", provider.getProviderId());
    }

    @Test
    void exposesConfiguredApiBaseUrl() {
        assertEquals(API_BASE, provider.getApiBaseUrl());
    }

    @Test
    void rejectsInvalidHashLength() {
        assertThrows(IllegalArgumentException.class,
                () -> provider.signHash(new byte[16], "user-token"));
    }

    @Test
    void rejectsMultipleCertificatesWithoutAlias() {
        apiClient.certificates = List.of(
                new RemoteIdApiClient.RemoteIdCertificate("A", credentials.certificate()),
                new RemoteIdApiClient.RemoteIdCertificate("B", credentials.certificate())
        );

        assertThrows(PscSigningException.class,
                () -> provider.getSignerCertificate("user-token"));
    }

    @Test
    void builderRejectsBlankApiBaseUrl() {
        assertThrows(IllegalArgumentException.class, () -> new RemoteIdProviderBuilder()
                .withClientId("id")
                .withClientSecret("secret")
                .withApiBaseUrl(" ")
                .build());
    }

    @Test
    void builderRejectsMissingApiBaseUrl() {
        assertThrows(IllegalArgumentException.class, () -> new RemoteIdProviderBuilder()
                .withClientId("id")
                .withClientSecret("secret")
                .build());
    }

    @Test
    void oauth2BuildsAuthorizationUrlWithConfiguredBase() {
        RemoteIdProvider built = (RemoteIdProvider) new RemoteIdProviderBuilder()
                .withClientId("id")
                .withClientSecret("secret")
                .withApiBaseUrl(API_BASE)
                .build();

        var pkce = built.oauth2().generatePkceChallenge();
        String authUrl = built.oauth2().buildAuthorizationUrl(
                pkce,
                "https://app/callback",
                "state"
        );

        assertTrue(authUrl.startsWith(API_BASE + "/v0/oauth/authorize"));
    }

    private static final class RecordingRemoteIdGateway implements RemoteIdGateway {

        List<RemoteIdApiClient.RemoteIdCertificate> certificates = List.of();
        byte[] rawSignature = new byte[0];
        String lastAccessToken;
        String lastCertificateAlias;
        DigestAlgorithm lastDigestAlgorithm;
        int discoveryCalls;

        @Override
        public List<RemoteIdApiClient.RemoteIdCertificate> discoverCertificates(String accessToken) {
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
