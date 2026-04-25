package dev.trustforge;

/** Thrown when the tf-daemon call cannot be completed. */
public class TrustForgeException extends RuntimeException {
    public TrustForgeException(String message) { super(message); }
    public TrustForgeException(String message, Throwable cause) { super(message, cause); }
}
