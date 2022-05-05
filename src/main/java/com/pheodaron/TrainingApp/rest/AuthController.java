package com.pheodaron.TrainingApp.rest;

import com.pheodaron.TrainingApp.dto.*;
import com.pheodaron.TrainingApp.service.impl.AuthenticationService;
import com.pheodaron.TrainingApp.service.impl.RefreshTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/app")
public class AuthController {
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationService authenticationService;

    public AuthController(
            RefreshTokenService refreshTokenService,
            AuthenticationService authenticationService
    ) {
        this.refreshTokenService = refreshTokenService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticationUser(@RequestBody LoginRequest loginRequest) {
        return authenticationService.authenticationUser(loginRequest);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        return authenticationService.registerUser(signupRequest);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(refreshTokenService.refreshToken(request.getRefreshToken()));
    }
}
