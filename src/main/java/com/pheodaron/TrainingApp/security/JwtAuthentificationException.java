package com.pheodaron.TrainingApp.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;

public class JwtAuthentificationException extends AuthenticationException {
    private HttpStatus httpStatus;

    public JwtAuthentificationException(String msg) {
        super(msg);
    }

    public JwtAuthentificationException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }


}
