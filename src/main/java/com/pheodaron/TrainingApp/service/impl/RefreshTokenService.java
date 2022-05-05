package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.dto.RefreshTokenResponse;
import com.pheodaron.TrainingApp.exceptions.TokenRefreshException;
import com.pheodaron.TrainingApp.model.RefreshToken;
import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.RefreshTokenRepository;
import com.pheodaron.TrainingApp.repository.UserRepository;
import com.pheodaron.TrainingApp.security.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Value("${jwt.refreshExpirationMs}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository, JwtTokenProvider jwtTokenProvider) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {
        deleteByUserId(userId);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userRepository.findById(userId).get());
        refreshToken.setExpiryDate(Date.from(Instant.now().plusMillis(refreshTokenDurationMs)));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken = refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Date.from(Instant.now())) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }

    public RefreshTokenResponse refreshToken(String requestRefreshToken) {
        RefreshToken refreshToken = findByToken(requestRefreshToken).orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                "Refresh token is not in database!"));
        refreshToken = verifyExpiration(refreshToken);
        User user = refreshToken.getUser();
        String accessToken = jwtTokenProvider.createAccessTokenFromUsername(user.getUsername());
        return new RefreshTokenResponse(accessToken, refreshToken.getToken());
    }
}
