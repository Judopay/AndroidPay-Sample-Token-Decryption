package com.judopay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link NetworkTokenDecryptionUtil}.
 */
@RunWith(JUnit4.class)
public class NetworkTokenDecryptionUtilTest {

    /**
     * Created with:
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -in merchant-key.pem -nocrypt
     */
    private static final String MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
                    + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
                    + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

    private static final String ENCRYPTED_PAYLOAD = "{"
            + "\"encryptedMessage\":\"PHxZxBQvVWwP\","
            + "\"ephemeralPublicKey\":\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI\\/zos5whGCQBlgOkuYagOis7qsrcbQrcpr"
            + "jvTZO3XOU+Qbcc28FSgsRtcgQE=\","
            + "\"tag\":\"TNwa3Q2WiyGi\\/eDA4XYVklq08KZiSxB7xvRiKK3H7kE=\"}";

    private NetworkTokenDecryptionUtil util;

    @Before
    public void setUp() {
        byte[] bytes = Base64.decode(MERCHANT_PRIVATE_KEY_PKCS8_BASE64.getBytes());

        NetworkTokenDecryptionUtil.setupSecurityProviderIfNecessary();
        util = NetworkTokenDecryptionUtil.createFromPkcs8EncodedPrivateKey(bytes);
    }

    @Test
    public void testShouldDecrypt() {
        assertEquals("plaintext", util.verifyThenDecrypt(ENCRYPTED_PAYLOAD));
    }

    @Test
    public void testShouldFailIfBadTag() throws Exception {
        JSONObject payload = new JSONObject(ENCRYPTED_PAYLOAD);
        byte[] tag = Base64.decode(payload.getString("tag"));
        // Messing with the first byte
        tag[0] = (byte) ~tag[0];
        payload.put("tag", new String(Base64.encode(tag)));

        try {
            util.verifyThenDecrypt(payload.toString());
            fail();
        } catch (RuntimeException e) {
            assertEquals("Bad Message Authentication Code!", e.getMessage());
        }
    }

    @Test
    public void testShouldFailIfEncryptedMessageWasChanged() throws Exception {
        JSONObject payload = new JSONObject(ENCRYPTED_PAYLOAD);
        byte[] encryptedMessage = Base64.decode(payload.getString("encryptedMessage"));
        // Messing with the first byte
        encryptedMessage[0] = (byte) ~encryptedMessage[0];
        payload.put("encryptedMessage", new String(Base64.encode(encryptedMessage)));

        try {
            util.verifyThenDecrypt(payload.toString());
            fail();
        } catch (RuntimeException e) {
            assertEquals("Bad Message Authentication Code!", e.getMessage());
        }
    }
}