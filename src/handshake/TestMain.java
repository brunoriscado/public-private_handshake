package handshake;

import handshake.exceptions.HandshakeErrorException;
import handshake.exceptions.HandshakeException;

public class TestMain {
    public static void main (String [] args) throws HandshakeException, HandshakeErrorException {
        String publicKeyLocation = "/web/config/handshake/.key/public.key";
        String privateKeyLocation = "/web/config/handshake/.key/private.key";
        String dataToEncrypt = "This is a string to be encrypted";

        Encrypter encrypter = new Encrypter();
        encrypter.setPublicKeyPath(publicKeyLocation);

        Decrypter decrypter = new Decrypter();
        decrypter.setPrivateKeyPath(privateKeyLocation);

        String encryptedData = encrypter.encrypt(dataToEncrypt);
        System.out.println("Encrypted data:\n" + encryptedData);
        System.out.println("Decrypted data:\n" + decrypter.decrypt(encryptedData));
        
    }
}
