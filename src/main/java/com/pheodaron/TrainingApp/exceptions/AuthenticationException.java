package com.pheodaron.TrainingApp.exceptions;

import org.springframework.http.HttpStatus;

public class AuthenticationException extends org.springframework.security.core.AuthenticationException {
    private HttpStatus httpStatus;

    public AuthenticationException(String msg) {
        super(msg);
    }

    public AuthenticationException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
