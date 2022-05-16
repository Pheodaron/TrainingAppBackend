package com.pheodaron.TrainingApp.rest;

import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.service.UserService;
import com.pheodaron.TrainingApp.service.impl.TestService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/app/test")
public class TestController {

    private final UserService userService;
    private final TestService testService;

    public TestController(UserService userService, TestService testService) {
        this.userService = userService;
        this.testService = testService;
    }

    private Set<String> testSet = Set.of(
            "test-data-1",
            "test-data-2",
            "test-data-3",
            "test-data-4"
    );

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/get")
    public Set<String> getAll() {
        return testSet;
    }

    @PreAuthorize("hasRole('USER')  or hasRole('ADMIN')")
    @GetMapping("/testExceptionHandler")
    public ResponseEntity<?> testExceptionHandler(@RequestParam("message") String message) {
        return testService.testErrorException(message);
    }

    @GetMapping("/get/{username}")
    public User getUserByEmail(@PathVariable String username) {
        return userService.findByUsername(username);
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')  or hasRole('ADMIN')")
    public String userAccess() {
        return "User Here.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Here.";
    }
}
