package com.pheodaron.TrainingApp.dto;

import lombok.Data;

import java.util.Set;

@Data
public class SignupRequest {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private Set<String> role;
    private String password;
}
