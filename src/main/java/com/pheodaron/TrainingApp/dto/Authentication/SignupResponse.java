package com.pheodaron.TrainingApp.dto.Authentication;

import lombok.Data;

@Data
public class SignupResponse {
    private String message;

    public SignupResponse(String message) {
        this.message = message;
    }
}
