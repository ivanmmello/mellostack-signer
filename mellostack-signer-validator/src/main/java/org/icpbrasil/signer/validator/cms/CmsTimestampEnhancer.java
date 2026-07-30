package org.icpbrasil.signer.validator.cms;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TSPException;
import org.icpbrasil.signer.core.pdf.DigestAlgorithm;
import org.icpbrasil.signer.validator.act.ActException;
import org.icpbrasil.signer.validator.act.TimestampAuthority;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

/**
 * Adiciona atributo não assinado {@code signatureTimeStampToken} (PAdES-T) ao CMS.
 */
public final class CmsTimestampEnhancer {

    private CmsTimestampEnhancer() {
    }

    /**
     * Solicita carimbo do tempo sobre o valor da assinatura CMS e retorna PKCS#7 PAdES-T.
     */
    public static byte[] enhance(byte[] cmsBytes, TimestampAuthority timestampAuthority)
            throws CMSException, IOException, TSPException {
        if (cmsBytes == null || cmsBytes.length == 0) {
            throw new IllegalArgumentException("cmsBytes must not be empty");
        }
        if (timestampAuthority == null) {
            throw new IllegalArgumentException("timestampAuthority must not be null");
        }

        CMSSignedData signedData = new CMSSignedData(cmsBytes);
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            throw new ActException("CMS envelope does not contain signer information");
        }

        List<SignerInformation> enhancedSigners = new ArrayList<>();
        for (SignerInformation signer : signers) {
            enhancedSigners.add(enhanceSigner(signer, timestampAuthority));
        }

        CMSSignedData enhanced = CMSSignedData.replaceSigners(
                signedData,
                new SignerInformationStore(enhancedSigners)
        );
        return enhanced.getEncoded();
    }

    private static SignerInformation enhanceSigner(
            SignerInformation signer,
            TimestampAuthority timestampAuthority) throws IOException, CMSException, TSPException {
        byte[] signatureValue = signer.getSignature();
        if (signatureValue == null || signatureValue.length == 0) {
            throw new ActException("CMS signer does not contain a signature value");
        }

        DigestAlgorithm imprintAlgorithm = DigestAlgorithm.SHA256;
        byte[] imprint = hashSignatureValue(signatureValue, imprintAlgorithm);
        byte[] tokenBytes = timestampAuthority.requestTimestampToken(imprint, imprintAlgorithm);

        TimeStampToken token = new TimeStampToken(new CMSSignedData(tokenBytes));
        Attribute timestampAttribute = new Attribute(
                PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                new DERSet(token.toCMSSignedData().toASN1Structure())
        );

        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        Hashtable<Object, Object> table = unsignedAttributes == null
                ? new Hashtable<>()
                : new Hashtable<>(unsignedAttributes.toHashtable());
        table.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, timestampAttribute);
        AttributeTable updated = new AttributeTable(table);

        return SignerInformation.replaceUnsignedAttributes(signer, updated);
    }

    private static byte[] hashSignatureValue(byte[] signatureValue, DigestAlgorithm algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm.jcaName());
            return digest.digest(signatureValue);
        } catch (Exception e) {
            throw new ActException("Failed to hash CMS signature value for timestamp imprint", e);
        }
    }
}
