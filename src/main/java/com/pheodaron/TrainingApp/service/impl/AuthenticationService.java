package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.dto.*;
import com.pheodaron.TrainingApp.enums.ERole;
import com.pheodaron.TrainingApp.enums.Status;
import com.pheodaron.TrainingApp.model.RefreshToken;
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
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthenticationService(
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
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is not found!"));
        }
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        JwtUser userDetails = (JwtUser) authentication.getPrincipal();
        List<Role> roles = getListOfRoles(userDetails.getAuthorities());

        String accessToken = tokenService.createAccessToken(userDetails.getUsername(), roles);
        String refreshToken = tokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(
            new SignupResponse(
                    accessToken,
                    refreshToken,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    getListOfStrings(roles)
            ));
    }

    public ResponseEntity<?> registerUser(SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
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

        return ResponseEntity.ok(new MessageResponse("User registered successfully"));
    }

    public ResponseEntity<?> logoutUser(Long userId) {
        tokenService.deleteRefreshTokenByUserId(userId);
        return ResponseEntity.ok(new MessageResponse("logout!"));
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
