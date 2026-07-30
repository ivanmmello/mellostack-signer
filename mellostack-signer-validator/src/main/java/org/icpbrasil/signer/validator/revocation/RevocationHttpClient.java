package org.icpbrasil.signer.validator.revocation;

import java.io.IOException;

/**
 * Cliente HTTP para download de CRL e consultas OCSP.
 */
public interface RevocationHttpClient {

    byte[] get(String url) throws IOException;

    byte[] post(String url, String contentType, byte[] body) throws IOException;
}
