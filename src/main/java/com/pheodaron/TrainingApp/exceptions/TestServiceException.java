package com.pheodaron.TrainingApp.exceptions;

public class TestServiceException extends RuntimeException{
    public TestServiceException() {
        super();
    }

    public TestServiceException(String message) {
        super(message);
    }
}
