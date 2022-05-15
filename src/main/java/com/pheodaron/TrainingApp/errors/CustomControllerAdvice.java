package com.pheodaron.TrainingApp.errors;

import com.pheodaron.TrainingApp.exceptions.UserAlreadyExistException;
import com.pheodaron.TrainingApp.exceptions.UserNotFoundByUsernameException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.io.PrintWriter;
import java.io.StringWriter;

@ControllerAdvice
public class CustomControllerAdvice {

    @ExceptionHandler(UserNotFoundByUsernameException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(Exception e) {
        HttpStatus status = HttpStatus.NOT_FOUND;

        return new ResponseEntity<>(new ErrorResponse(status, e.getMessage()), status);
    }

    @ExceptionHandler(UserAlreadyExistException.class)
    public ResponseEntity<ErrorResponse> handleUserExistException(Exception e) {
        HttpStatus status = HttpStatus.CONFLICT;

        return new ResponseEntity<>(new ErrorResponse(status, e.getMessage()), status);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(Exception e){
        HttpStatus status = HttpStatus.FORBIDDEN;

        return new ResponseEntity<>(new ErrorResponse(status,"Forbidden"), status);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception e) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        e.printStackTrace(printWriter);
        String stackTrace = stringWriter.toString();

        return new ResponseEntity<>(new ErrorResponse(status, e.getMessage(), stackTrace), status);
    }
}
