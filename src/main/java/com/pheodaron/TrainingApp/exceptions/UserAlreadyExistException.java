package com.pheodaron.TrainingApp.exceptions;

public class UserAlreadyExistException extends RuntimeException{
    public UserAlreadyExistException() {
        super();
    }

    public UserAlreadyExistException(String message) {
        super(message);
    }
}
