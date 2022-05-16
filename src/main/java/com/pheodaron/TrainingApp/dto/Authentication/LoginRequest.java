package com.pheodaron.TrainingApp.dto.Authentication;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
