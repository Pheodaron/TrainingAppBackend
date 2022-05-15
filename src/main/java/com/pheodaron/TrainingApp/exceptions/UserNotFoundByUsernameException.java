package com.pheodaron.TrainingApp.exceptions;

public class UserNotFoundByUsernameException extends RuntimeException{
    public UserNotFoundByUsernameException() {
        super();
    }

    public UserNotFoundByUsernameException(String message) {
        super(message);
    }
}
