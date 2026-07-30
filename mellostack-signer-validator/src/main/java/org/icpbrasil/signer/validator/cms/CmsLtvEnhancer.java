package org.icpbrasil.signer.validator.cms;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;

/**
 * Incorpora dados de revogação (CRL/OCSP) no CMS para validação de longo prazo (PAdES-LTV).
 */
public final class CmsLtvEnhancer {

    private CmsLtvEnhancer() {
    }

    /**
     * Adiciona atributo não assinado {@code id-aa-ets-revocationValues} ao CMS.
     */
    public static byte[] enhance(byte[] cmsBytes, LtvRevocationData revocationData)
            throws CMSException, IOException {
        Objects.requireNonNull(cmsBytes, "cmsBytes");
        Objects.requireNonNull(revocationData, "revocationData");
        if (revocationData.isEmpty()) {
            throw new IllegalArgumentException("revocationData must contain at least one CRL or OCSP response");
        }

        CMSSignedData signedData = new CMSSignedData(cmsBytes);
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            throw new IllegalStateException("CMS envelope does not contain signer information");
        }

        RevocationValues revocationValues = buildRevocationValues(revocationData);
        Attribute revocationAttribute = new Attribute(
                PKCSObjectIdentifiers.id_aa_ets_revocationValues,
                new DERSet(revocationValues)
        );

        List<SignerInformation> enhancedSigners = new ArrayList<>();
        for (SignerInformation signer : signers) {
            Hashtable<Object, Object> table = signer.getUnsignedAttributes() == null
                    ? new Hashtable<>()
                    : new Hashtable<>(signer.getUnsignedAttributes().toHashtable());
            table.put(PKCSObjectIdentifiers.id_aa_ets_revocationValues, revocationAttribute);
            enhancedSigners.add(SignerInformation.replaceUnsignedAttributes(
                    signer,
                    new AttributeTable(table)
            ));
        }

        CMSSignedData enhanced = CMSSignedData.replaceSigners(
                signedData,
                new SignerInformationStore(enhancedSigners)
        );
        return enhanced.getEncoded();
    }

    private static RevocationValues buildRevocationValues(LtvRevocationData revocationData) throws IOException {
        CertificateList[] crlValues = revocationData.crlResponses().stream()
                .map(CmsLtvEnhancer::parseCrl)
                .toArray(CertificateList[]::new);
        BasicOCSPResponse[] ocspValues = revocationData.ocspResponses().stream()
                .map(CmsLtvEnhancer::parseOcsp)
                .toArray(BasicOCSPResponse[]::new);
        return new RevocationValues(crlValues, ocspValues, null);
    }

    private static CertificateList parseCrl(byte[] crlBytes) {
        try (ASN1InputStream input = new ASN1InputStream(crlBytes)) {
            return CertificateList.getInstance(input.readObject());
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid CRL bytes for LTV embedding", e);
        }
    }

    private static BasicOCSPResponse parseOcsp(byte[] ocspBytes) {
        try {
            OCSPResp ocspResp = new OCSPResp(ocspBytes);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                throw new IllegalArgumentException("OCSP response status is not successful");
            }
            return BasicOCSPResponse.getInstance(ocspResp.getResponseObject());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid OCSP response bytes for LTV embedding", e);
        }
    }
}
