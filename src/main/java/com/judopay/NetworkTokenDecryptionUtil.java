package com.judopay;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Utility for decrypting encrypted network tokens as per Android Pay InApp spec. */
class NetworkTokenDecryptionUtil {

    private static final String SECURITY_PROVIDER = "BC";
    private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
    private static final String ASYMMETRIC_KEY_TYPE = "EC";
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";
    /** OpenSSL name of the NIST P-126 Elliptic Curve */
    private static final String EC_CURVE = "prime256v1";
    private static final String SYMMETRIC_KEY_TYPE = "AES";
    private static final String SYMMETRIC_ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] SYMMETRIC_IV = Hex.decode("00000000000000000000000000000000");
    private static final int SYMMETRIC_KEY_BYTE_COUNT = 16;
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final int MAC_KEY_BYTE_COUNT = 16;
    private static final byte[] HKDF_INFO = "Android".getBytes(DEFAULT_CHARSET);
    private static final byte[] HKDF_SALT = null /* equivalent to a zeroed salt of hashLen */;

    private PrivateKey privateKey;

    private NetworkTokenDecryptionUtil(PrivateKey privateKey) {
        if (!ASYMMETRIC_KEY_TYPE.equals(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("Unexpected type of private key");
        }
        this.privateKey = privateKey;
    }

    public static NetworkTokenDecryptionUtil createFromPkcs8EncodedPrivateKey(byte[] pkcs8PrivateKey) {
        PrivateKey privateKey;
        try {
            KeyFactory asymmetricKeyFactory =
                    KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);
            privateKey = asymmetricKeyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(pkcs8PrivateKey));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to create NetworkTokenDecryptionUtil", e);
        }
        return new NetworkTokenDecryptionUtil(privateKey);
    }

    /**
     * Sets up the {@link #SECURITY_PROVIDER} if not yet set up.
     *
     *You must call this method at least once before using this class.
     */
    public static void setupSecurityProviderIfNecessary() {
        if (Security.getProvider(SECURITY_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Verifies then decrypts the given payload according to the Android Pay Network Token
     * encryption spec.
     */
    public String verifyThenDecrypt(String encryptedPayloadJson) {
        try {
            JSONObject object = new JSONObject(encryptedPayloadJson);
            byte[] ephemeralPublicKeyBytes =
                    Base64.decode(object.getString("ephemeralPublicKey"));
            byte[] encryptedMessage = Base64.decode(object.getString("encryptedMessage"));
            byte[] tag = Base64.decode(object.getString("tag"));

            // Parsing public key.
            ECParameterSpec asymmetricKeyParams = generateECParameterSpec();
            KeyFactory asymmetricKeyFactory =
                    KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);
            PublicKey ephemeralPublicKey = asymmetricKeyFactory.generatePublic(
                    new ECPublicKeySpec(
                            ECPointUtil.decodePoint(asymmetricKeyParams.getCurve(), ephemeralPublicKeyBytes),
                            asymmetricKeyParams));

            // Deriving shared secret.
            KeyAgreement keyAgreement =
                    KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, SECURITY_PROVIDER);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(ephemeralPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Deriving encryption and mac keys.
            HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
            byte[] khdfInput = ByteUtils.concatenate(ephemeralPublicKeyBytes, sharedSecret);
            hkdfBytesGenerator.init(new HKDFParameters(khdfInput, HKDF_SALT, HKDF_INFO));
            byte[] encryptionKey = new byte[SYMMETRIC_KEY_BYTE_COUNT];
            hkdfBytesGenerator.generateBytes(encryptionKey, 0, SYMMETRIC_KEY_BYTE_COUNT);
            byte[] macKey = new byte[MAC_KEY_BYTE_COUNT];
            hkdfBytesGenerator.generateBytes(macKey, 0, MAC_KEY_BYTE_COUNT);

            // Verifying Message Authentication Code (aka mac/tag)
            Mac macGenerator = Mac.getInstance(MAC_ALGORITHM, SECURITY_PROVIDER);
            macGenerator.init(new SecretKeySpec(macKey, MAC_ALGORITHM));
            byte[] expectedTag = macGenerator.doFinal(encryptedMessage);
            if (!isArrayEqual(tag, expectedTag)) {
                throw new RuntimeException("Bad Message Authentication Code!");
            }

            // Decrypting the message.
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(encryptionKey, SYMMETRIC_KEY_TYPE),
                    new IvParameterSpec(SYMMETRIC_IV));
            return new String(cipher.doFinal(encryptedMessage), DEFAULT_CHARSET);
        } catch (JSONException | NoSuchAlgorithmException | NoSuchProviderException
                | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Failed verifying/decrypting message", e);
        }
    }

    private ECNamedCurveSpec generateECParameterSpec() {
        ECNamedCurveParameterSpec bcParams = ECNamedCurveTable.getParameterSpec(EC_CURVE);
        ECNamedCurveSpec params = new ECNamedCurveSpec(bcParams.getName(), bcParams.getCurve(),
                bcParams.getG(), bcParams.getN(), bcParams.getH(), bcParams.getSeed());
        return params;
    }

    /**
     * Fixed-timing array comparison.
     */
    public static boolean isArrayEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
