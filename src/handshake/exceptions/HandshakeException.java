package handshake.exceptions;

public class HandshakeException extends Exception {

    /**
     * Serial ID
     */
    private static final long serialVersionUID = -4346080736632905460L;

    public HandshakeException(String message) {
        super(message);
    }

    public HandshakeException(String message, Throwable cause) {
        super(message, cause);
    }
}