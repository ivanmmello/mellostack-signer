package org.icpbrasil.signer.validator.act;

import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalTimestampAuthorityTest {

    @Test
    void generatesTimestampTokenForImprint() throws Exception {
        LocalTimestampAuthority authority = LocalTimestampAuthority.generate();
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest(new byte[]{1, 2, 3});

        byte[] tokenBytes = authority.requestTimestampToken(imprint, DigestAlgorithm.SHA256);

        assertNotNull(tokenBytes);
        assertTrue(tokenBytes.length > 0);
        assertNotNull(new TimeStampToken(new org.bouncycastle.cms.CMSSignedData(tokenBytes)));
    }

    @Test
    void rejectsInvalidImprintLength() throws Exception {
        LocalTimestampAuthority authority = LocalTimestampAuthority.generate();
        assertThrows(IllegalArgumentException.class,
                () -> authority.requestTimestampToken(new byte[16], DigestAlgorithm.SHA256));
    }
}
