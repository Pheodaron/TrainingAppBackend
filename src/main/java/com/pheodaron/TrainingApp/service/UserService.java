package com.pheodaron.TrainingApp.service;

import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> getUserByEmail(String email) {
        return  userRepository.findByEmail(email);
    }
}
