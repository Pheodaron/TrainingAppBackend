package com.pheodaron.TrainingApp.rest;

import com.pheodaron.TrainingApp.dto.*;
import com.pheodaron.TrainingApp.service.impl.AuthenticationService;
import com.pheodaron.TrainingApp.service.impl.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/app")
public class AuthController {
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;

    public AuthController(
            AuthenticationService authenticationService,
            TokenService tokenService
    ) {
        this.authenticationService = authenticationService;
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticationUser(@RequestBody LoginRequest loginRequest) {
        return authenticationService.authenticationUser(loginRequest);
    }

    @GetMapping("/logout/{id}")
    public ResponseEntity<?> logout(@PathVariable Long id) {
        return authenticationService.logoutUser(id);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        return authenticationService.registerUser(signupRequest);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(tokenService.replaceRefreshToken(request.getRefreshToken()));
    }
}
