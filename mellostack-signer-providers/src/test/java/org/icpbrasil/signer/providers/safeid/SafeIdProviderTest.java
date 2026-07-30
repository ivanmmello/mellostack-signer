package org.icpbrasil.signer.providers.safeid;

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

class SafeIdProviderTest {

    private TestCertificateFactory.TestCredentials credentials;
    private RecordingSafeIdGateway apiClient;
    private SafeIdProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        credentials = TestCertificateFactory.generateRsa2048();
        apiClient = new RecordingSafeIdGateway();
        apiClient.certificates = List.of(new SafeIdApiClient.SafeIdCertificate(
                "CERT-SAFE:321",
                credentials.certificate()
        ));
        apiClient.rawSignature = new byte[]{7, 8, 9};

        provider = new SafeIdProvider(
                Environment.HOMOLOGATION,
                apiClient,
                SafeIdOAuth2Support.create(
                        Environment.HOMOLOGATION,
                        "client-id",
                        "client-secret",
                        HttpClientConfig.defaults()
                ),
                null,
                new SecureTokenCache<>(SafeIdProvider.CERTIFICATE_CACHE_TTL)
        );
    }

    @Test
    void signHashDelegatesToApiWithSha256() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("pdf".getBytes());

        byte[] signature = provider.signHash(hash, "user-token");

        assertArrayEquals(new byte[]{7, 8, 9}, signature);
        assertEquals("user-token", apiClient.lastAccessToken);
        assertEquals("CERT-SAFE:321", apiClient.lastCertificateAlias);
        assertEquals(DigestAlgorithm.SHA256, apiClient.lastDigestAlgorithm);
    }

    @Test
    void getProviderIdIsSafeId() {
        assertEquals("safeid", provider.getProviderId());
    }

    @Test
    void rejectsMultipleCertificatesWithoutAlias() {
        apiClient.certificates = List.of(
                new SafeIdApiClient.SafeIdCertificate("A", credentials.certificate()),
                new SafeIdApiClient.SafeIdCertificate("B", credentials.certificate())
        );

        assertThrows(PscSigningException.class,
                () -> provider.getSignerCertificate("user-token"));
    }

    @Test
    void builderRejectsBlankClientId() {
        assertThrows(IllegalArgumentException.class, () -> new SafeIdProviderBuilder()
                .withClientId(" ")
                .withClientSecret("secret")
                .build());
    }

    @Test
    void oauth2BuildsAuthorizationUrlWithHomologationBase() {
        SafeIdProvider built = (SafeIdProvider) new SafeIdProviderBuilder()
                .withClientId("id")
                .withClientSecret("secret")
                .withEnvironment(Environment.HOMOLOGATION)
                .build();

        var pkce = built.oauth2().generatePkceChallenge();
        String authUrl = built.oauth2().buildAuthorizationUrl(
                pkce,
                "https://app/callback",
                "state"
        );

        assertTrue(authUrl.startsWith(SafeIdEndpoints.baseUrl(Environment.HOMOLOGATION) + "/v0/oauth/authorize"));
    }

    private static final class RecordingSafeIdGateway implements SafeIdGateway {

        List<SafeIdApiClient.SafeIdCertificate> certificates = List.of();
        byte[] rawSignature = new byte[0];
        String lastAccessToken;
        String lastCertificateAlias;
        DigestAlgorithm lastDigestAlgorithm;

        @Override
        public List<SafeIdApiClient.SafeIdCertificate> discoverCertificates(String accessToken) {
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
