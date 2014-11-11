package handshake.exceptions;

public class HandshakeErrorException extends Exception {

    /**
     * Serial ID
     */
    private static final long serialVersionUID = 4935070697933151906L;

    public HandshakeErrorException(String message) {
        super(message);
    }

    public HandshakeErrorException(String message, Throwable cause) {
        super(message, cause);
    }
}