package com.beamedcallum.gateway.authorization.refresh.exceptions;

import com.beamedcallum.gateway.tokens.exceptions.TokenException;

public class TokenGenerationException extends TokenException {
    public TokenGenerationException() {
    }

    public TokenGenerationException(String message) {
        super(message);
    }

    public TokenGenerationException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenGenerationException(Throwable cause) {
        super(cause);
    }

    public TokenGenerationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
