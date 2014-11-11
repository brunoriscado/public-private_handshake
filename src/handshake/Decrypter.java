package handshake;

import handshake.exceptions.HandshakeErrorException;
import handshake.exceptions.HandshakeException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import com.google.gson.Gson;

public class Decrypter {
    private final static Logger LOG = Logger.getLogger(Decrypter.class.getCanonicalName());
    private final static String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private final static String ENCODING = "UTF-8";
    private String privateKeyPath;

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    private String decryptRSA(String cipherText) throws HandshakeException, HandshakeErrorException {
        LOG.log(Level.FINE, ">>> private key decryption <<<");
        String decryptRSA = null;
        FileInputStream in = null;
        try {
            in = new FileInputStream(getPrivateKeyPath());
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(in));
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec));
            decryptRSA = new String(cipher.doFinal(Base64.decodeBase64(cipherText)), ENCODING);
            LOG.log(Level.FINEST, ">>> ENCRYPTED DATA: " + cipherText + " decrypted to: " + decryptRSA + " <<<");
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
        return decryptRSA;
    }

    public String decrypt(String dataToDecrypt) throws HandshakeException, HandshakeErrorException {
        LOG.log(Level.FINE, ">>> decrypt <<<");
        Gson gson = new Gson();
        String[] data = null;
        try {
            data = gson.fromJson(dataToDecrypt, String[].class);
        } catch (Exception e) {
            LOG.log(Level.WARNING, ">>> The message is not encrypted or has an incorrect format <<<");
            throw new HandshakeException("The message is not encrypted or has an incorrect format");
        }
        String aesKey = null;
        String decryptedData = null;
        if (data != null && data.length == 2) {
            aesKey = decryptRSA(data[0]);
            decryptedData = decryptAES(aesKey, data[1]);
        }
        LOG.log(Level.FINEST, ">>> Decrypted data: " + decryptedData + " <<<");
        return decryptedData;
    }

    private String decryptAES(String key, String encrypted) throws HandshakeException {
        LOG.log(Level.FINE, ">>> decryptAES <<<");
        byte[] decryptionKey = Base64.decodeBase64(key);
        String decryptedValue = null;
        try {
            if (decryptionKey != null) {
                Key k = new SecretKeySpec(decryptionKey, "AES");
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, k);
                byte[] decodedValue = Base64.decodeBase64(encrypted);
                byte[] decValue = c.doFinal(decodedValue);
                decryptedValue = new String(decValue);
                LOG.log(Level.FINEST, ">>> AES Decrypted data: " + decryptedValue + " <<<");
            }
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(e.getMessage(), e.getCause()); 
        }
        return decryptedValue;
    }
}