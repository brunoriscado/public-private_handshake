package handshake;

import handshake.exceptions.HandshakeErrorException;
import handshake.exceptions.HandshakeException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

public class Encrypter {
    private final static Logger LOG = Logger.getLogger(Encrypter.class.getCanonicalName());
    private final static String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private final static String ENCODING = "UTF-8";
    private static byte[] AES_KEY = null;
    private String publicKeyPath;

    public String getPublicKeyPath() {
        return publicKeyPath;
    }

    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }

    private String encryptRSA(String rawText) throws HandshakeException, HandshakeErrorException {
        LOG.log(Level.FINE, ">>> public key encryption <<<");
        String encryptRSA = null;
        FileInputStream in = null;
        try {
            in = new FileInputStream(getPublicKeyPath());
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(IOUtils.toByteArray(in));
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec));
            encryptRSA = Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(ENCODING)));
            LOG.log(Level.FINEST, ">>> RAW DATA: " + rawText + " encrypted to: " + encryptRSA + " <<<");
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(e.getMessage(), e.getCause());
        } catch (IOException e) {
            throw new HandshakeErrorException(e.getMessage(), e.getCause());
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                LOG.log(Level.WARNING, ">>> Error closing the inputstream <<<");
                throw new HandshakeErrorException("Error closing the inputstream");
            }
        }
        return encryptRSA;
    }

    public String encrypt(String dataToEncrypt) throws HandshakeException, HandshakeErrorException {
        LOG.log(Level.FINE, ">>> encrypt <<<");
        String[] encryptedData = null;
        generateAESKey();
        String rsaEncryptedAESKey = encryptRSA(getAESKey());
        String aesEncryptedData = encryptAES(dataToEncrypt);
        encryptedData = new String[] {rsaEncryptedAESKey, aesEncryptedData};
        LOG.log(Level.FINEST, ">>> Encrypted data: " + JSONObject.valueToString(encryptedData) + " <<<");
        return JSONObject.valueToString(encryptedData);
    }

    private String encryptAES(String value) throws HandshakeException {
        LOG.log(Level.FINE, ">>> encryptAES <<<");
        String encrypt = null;
        try {
            if (AES_KEY != null) {
                SecretKeySpec skeySpec = new SecretKeySpec(AES_KEY, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                encrypt = (new Base64()).encodeAsString(cipher.doFinal(value.getBytes()));
                LOG.log(Level.FINEST, ">>> AES Encrypted data: " + encrypt + " <<<");
            }
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(e.getMessage(), e.getCause());
        }
        return encrypt;
    }

    private void generateAESKey() throws HandshakeException {
        LOG.log(Level.FINE, ">>> generateAESKey <<<");
        try {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(256);
        SecretKey skey = kgen.generateKey();
        AES_KEY = skey.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(e.getMessage(), e.getCause());
        }
    }

    private static String getAESKey() {
        LOG.log(Level.FINE, ">>> getAESKey - AES Key: " + Base64.encodeBase64String(AES_KEY) + " <<<");
        return Base64.encodeBase64String(AES_KEY);
    }
}