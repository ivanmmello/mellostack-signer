package org.icpbrasil.signer.providers.birdid;

import org.icpbrasil.signer.core.cms.TestCertificateFactory;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.model.Environment;
import org.icpbrasil.signer.providers.exception.PscSigningException;
import org.icpbrasil.signer.providers.http.HttpClientConfig;
import org.icpbrasil.signer.providers.http.SecureHttpClient;
import org.icpbrasil.signer.providers.security.SecureTokenCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BirdIdProviderTest {

    private TestCertificateFactory.TestCredentials credentials;
    private RecordingBirdIdGateway apiClient;
    private BirdIdProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        credentials = TestCertificateFactory.generateRsa2048();
        apiClient = new RecordingBirdIdGateway();
        apiClient.certificates = List.of(new BirdIdApiClient.BirdIdCertificate(
                "CERT-TEST:123",
                credentials.certificate()
        ));
        apiClient.rawSignature = new byte[]{1, 2, 3, 4};

        provider = new BirdIdProvider(
                Environment.HOMOLOGATION,
                apiClient,
                BirdIdOAuth2Support.create(
                        Environment.HOMOLOGATION,
                        "client-id",
                        "client-secret",
                        HttpClientConfig.defaults()
                ),
                null,
                new SecureTokenCache<>(BirdIdProvider.CERTIFICATE_CACHE_TTL)
        );
    }

    @Test
    void signHashDelegatesToApiWithSha256() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("pdf".getBytes());

        byte[] signature = provider.signHash(hash, "user-token");

        assertArrayEquals(new byte[]{1, 2, 3, 4}, signature);
        assertEquals("user-token", apiClient.lastAccessToken);
        assertEquals("CERT-TEST:123", apiClient.lastCertificateAlias);
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
    void rejectsInvalidHashLength() {
        assertThrows(IllegalArgumentException.class,
                () -> provider.signHash(new byte[16], "user-token"));
    }

    @Test
    void rejectsMultipleCertificatesWithoutAlias() {
        apiClient.certificates = List.of(
                new BirdIdApiClient.BirdIdCertificate("A", credentials.certificate()),
                new BirdIdApiClient.BirdIdCertificate("B", credentials.certificate())
        );

        assertThrows(PscSigningException.class,
                () -> provider.getSignerCertificate("user-token"));
    }

    @Test
    void builderRejectsBlankClientSecret() {
        assertThrows(IllegalArgumentException.class, () -> new BirdIdProviderBuilder()
                .withClientId("id")
                .withClientSecret(" ")
                .build());
    }

    @Test
    void oauth2RejectsAuthenticationOnlyScopeForSigningUrl() {
        BirdIdProvider built = (BirdIdProvider) new BirdIdProviderBuilder()
                .withClientId("id")
                .withClientSecret("secret")
                .build();

        var pkce = built.oauth2().generatePkceChallenge();
        assertThrows(IllegalArgumentException.class, () -> built.oauth2().buildAuthorizationUrl(
                pkce,
                "https://app/callback",
                "state",
                org.icpbrasil.signer.providers.oauth.OAuth2Scope.AUTHENTICATION_SESSION,
                null,
                null
        ));
    }

    private static final class RecordingBirdIdGateway implements BirdIdGateway {

        List<BirdIdApiClient.BirdIdCertificate> certificates = List.of();
        byte[] rawSignature = new byte[0];
        String lastAccessToken;
        String lastCertificateAlias;
        DigestAlgorithm lastDigestAlgorithm;
        int discoveryCalls;

        @Override
        public List<BirdIdApiClient.BirdIdCertificate> discoverCertificates(String accessToken) {
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
