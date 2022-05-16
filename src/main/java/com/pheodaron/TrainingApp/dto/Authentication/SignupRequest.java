package com.pheodaron.TrainingApp.dto.Authentication;

import lombok.Data;

@Data
public class SignupRequest {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
