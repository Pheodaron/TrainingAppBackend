package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.dto.*;
import com.pheodaron.TrainingApp.enums.ERole;
import com.pheodaron.TrainingApp.enums.Status;
import com.pheodaron.TrainingApp.model.RefreshToken;
import com.pheodaron.TrainingApp.model.Role;
import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.RoleRepository;
import com.pheodaron.TrainingApp.repository.UserRepository;
import com.pheodaron.TrainingApp.security.jwt.JwtTokenProvider;
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
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    public AuthenticationService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            PasswordEncoder encoder,
            RoleRepository roleRepository,
            JwtTokenProvider jwtTokenProvider,
            RefreshTokenService refreshTokenService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.roleRepository = roleRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
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

        String accessToken = jwtTokenProvider.createAccessToken(userDetails.getUsername(), roles);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(
            new SignupResponse(
                    accessToken,
                    refreshToken.getToken(),
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

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
//            strRoles.forEach(role -> {
//                switch (role.toLowerCase(Locale.ROOT)) {
//                    case "admin":
//                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                        roles.add(adminRole);
//
//                        break;
//
//                    default:
//                        Role userRole = roleRepository.findByName(ERole.ROLE_USER.name());
//                        roles.add(userRole);
//                }
//            });
            return ResponseEntity.badRequest().body(new MessageResponse("Please, repeat without roles(roles will coming in future update!)"));
        }
        user.setRoles(new ArrayList<>(roles));
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully"));
    }

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
