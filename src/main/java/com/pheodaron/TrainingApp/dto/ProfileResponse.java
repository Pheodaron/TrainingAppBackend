package com.pheodaron.TrainingApp.dto;

import lombok.Data;

import java.util.List;

@Data
public class ProfileResponse {
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private List<String> roles;

    public ProfileResponse(
            String username,
            String firstName,
            String lastName,
            String email,
            List<String> roles
    ) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.roles = roles;
    }
}
