package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.exceptions.TestServiceException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class TestService {


    public ResponseEntity<?> testErrorException(String message) {
        if (message.equals("yes")) {
            throw new TestServiceException();
        } else {
            return ResponseEntity.ok("Все кулл!");
        }
    }
}
