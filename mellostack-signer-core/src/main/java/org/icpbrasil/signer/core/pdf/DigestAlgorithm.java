package org.icpbrasil.signer.core.pdf;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Algoritmos de digest suportados para PAdES (conformidade ICP-Brasil V12).
 */
public enum DigestAlgorithm {

    SHA256("SHA-256"),
    SHA384("SHA-384");

    private final String jcaName;

    DigestAlgorithm(String jcaName) {
        this.jcaName = jcaName;
    }

    public String jcaName() {
        return jcaName;
    }

    public MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance(jcaName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest algorithm not available: " + jcaName, e);
        }
    }
}
