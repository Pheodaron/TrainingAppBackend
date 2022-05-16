package com.pheodaron.TrainingApp.rest;

import com.pheodaron.TrainingApp.dto.Authentication.LoginRequest;
import com.pheodaron.TrainingApp.dto.Authentication.RefreshTokenRequest;
import com.pheodaron.TrainingApp.dto.Authentication.SignupRequest;
import com.pheodaron.TrainingApp.service.UserService;
import com.pheodaron.TrainingApp.service.impl.AuthService;
import com.pheodaron.TrainingApp.service.impl.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/app")
public class AuthController {
    private final TokenService tokenService;
    private final AuthService authService;
    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    public AuthController(
            AuthService authService,
            TokenService tokenService,
            UserService userService,
            AuthenticationManager authenticationManager
    ) {
        this.authService = authService;
        this.tokenService = tokenService;
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticationUser(@RequestBody LoginRequest loginRequest) {
        return authService.authenticationUser(loginRequest);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        return authService.registerUser(signupRequest);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        return tokenService.replaceRefreshToken(request.getRefreshToken());
    }
}
