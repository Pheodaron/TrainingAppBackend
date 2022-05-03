package com.pheodaron.TrainingApp.rest;

import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/test")
public class TestController {

    private final UserService userService;

    public TestController(UserService userService) {
        this.userService = userService;
    }

    private Set<String> testSet = Set.of(
            "test-data-1",
            "test-data-2",
            "test-data-3",
            "test-data-4"
    );

    @GetMapping("/get")
    public Set<String> getAll() {
        return testSet;
    }

    @GetMapping("/get/{username}")
    public User getUserByEmail(@PathVariable String username) {
        return userService.findByUsername(username);
    }
}
