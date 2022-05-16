package com.pheodaron.TrainingApp.rest;

import com.pheodaron.TrainingApp.service.impl.UserServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class UserController {

    private final UserServiceImpl userService;

    public UserController(UserServiceImpl userService) {
        this.userService = userService;
    };

    @GetMapping("/get/{username}")
    public ResponseEntity<?> getUserByEmail(@PathVariable String username) {
        return userService.getUserProfileByUsername(username);
    }
}
