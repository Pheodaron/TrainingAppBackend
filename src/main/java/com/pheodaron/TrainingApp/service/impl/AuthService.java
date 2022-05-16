package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.dto.Authentication.LoginRequest;
import com.pheodaron.TrainingApp.dto.Authentication.LoginResponse;
import com.pheodaron.TrainingApp.dto.Authentication.SignupRequest;
import com.pheodaron.TrainingApp.dto.Authentication.SignupResponse;
import com.pheodaron.TrainingApp.enums.ERole;
import com.pheodaron.TrainingApp.enums.Status;
import com.pheodaron.TrainingApp.exceptions.UserAlreadyExistException;
import com.pheodaron.TrainingApp.exceptions.UserNotFoundByUsernameException;
import com.pheodaron.TrainingApp.model.Role;
import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.RoleRepository;
import com.pheodaron.TrainingApp.repository.UserRepository;
import com.pheodaron.TrainingApp.security.jwt.JwtUser;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            PasswordEncoder encoder,
            RoleRepository roleRepository,
            TokenService tokenService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.roleRepository = roleRepository;
        this.tokenService = tokenService;
    }

    public ResponseEntity<?> authenticationUser(LoginRequest loginRequest) {
        if(!userRepository.existsByUsername(loginRequest.getUsername())) {
            throw new UserNotFoundByUsernameException("User with username " + loginRequest.getUsername() + " not found!");
        }
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        JwtUser userDetails = (JwtUser) authentication.getPrincipal();
        List<Role> roles = getListOfRoles(userDetails.getAuthorities());

        String accessToken = tokenService.createAccessToken(userDetails.getUsername(), roles);
        String refreshToken = tokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }

    public ResponseEntity<?> registerUser(SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new UserAlreadyExistException("User with username: " + signupRequest.getUsername() + " already exists!");
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new UserAlreadyExistException("User with email: " + signupRequest.getEmail() + " already exists!");
        }
        User user = new User(
                signupRequest.getUsername(),
                signupRequest.getFirstName(),
                signupRequest.getLastName(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()),
                Status.ACTIVE
        );

        user.setRoles(List.of(roleRepository.findByName(ERole.ROLE_USER.name())));
        userRepository.save(user);

        return ResponseEntity.ok(new SignupResponse("User registered successfully!"));
    }

    //support methods-------------------------------------------------------

    public List<Role> getListOfRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(
                        item -> roleRepository.findByName(item.getAuthority())
                ).collect(Collectors.toList());
    }

    public List<String> getListOfStrings(List<Role> roles) {
        return roles.stream().map(Role::getName).collect(Collectors.toList());
    }
}
