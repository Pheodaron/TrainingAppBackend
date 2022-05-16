package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.dto.ProfileResponse;
import com.pheodaron.TrainingApp.enums.Status;
import com.pheodaron.TrainingApp.model.Role;
import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.RoleRepository;
import com.pheodaron.TrainingApp.repository.UserRepository;
import com.pheodaron.TrainingApp.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User register(User user) {
        Role roleUser = roleRepository.findByName("ROLE_USER");
        List<Role> userRoles = new ArrayList<>();
        userRoles.add(roleUser);

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(userRoles);
        user.setStatus(Status.ACTIVE);

        User registeredUser = userRepository.save(user);

        System.out.printf("user %s successfully registered", user.getUsername());

        return registeredUser;
    }

    @Override
    public List<User> getAll() {
        List<User> result = userRepository.findAll();

        System.out.printf("%d users successfully founded", result.size());
        return result;
    }

    @Override
    public User findByUsername(String username) {
        User result = userRepository.findByUsername(username);

        System.out.printf("%s is founded", result.getUsername());
        return result;
    }

    @Override
    public User findById(Long id) {
        Optional<User> result = userRepository.findById(id);

        return result.orElse(null);
    }

    @Override
    public void delete(Long id) {
        userRepository.deleteById(id);
    }

    public Optional<User> getUserByEmail(String email) {
        return  userRepository.findByEmail(email);
    }

    public ResponseEntity<?> getUserProfileByUsername(String username) {
        User user = findByUsername(username);

        return ResponseEntity.ok(
                new ProfileResponse(
                        user.getUsername(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getEmail(),
                        getListOfStrings(user.getRoles())));
    }

    public List<String> getListOfStrings(List<Role> roles) {
        return roles.stream().map(Role::getName).collect(Collectors.toList());
    }
}
