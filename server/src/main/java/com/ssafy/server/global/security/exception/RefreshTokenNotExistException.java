package com.ssafy.server.global.security.exception;

public class RefreshTokenNotExistException extends RuntimeException {
    public RefreshTokenNotExistException(String message) {
        super(message);
    }
}
