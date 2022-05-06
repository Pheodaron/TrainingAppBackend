package com.pheodaron.TrainingApp.service.impl;

import com.pheodaron.TrainingApp.dto.RefreshTokenResponse;
import com.pheodaron.TrainingApp.exceptions.JwtAuthenticationException;
import com.pheodaron.TrainingApp.exceptions.TokenRefreshException;
import com.pheodaron.TrainingApp.model.RefreshToken;
import com.pheodaron.TrainingApp.model.Role;
import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.RefreshTokenRepository;
import com.pheodaron.TrainingApp.repository.UserRepository;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class TokenService {

    @Value("${jwt.header}")
    private String authorizationHeader;
    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.accessTokenDurationMins}")
    private Long accessTokenDurationMins;
    @Value("${jwt.refreshTokenDurationDays}")
    private Long refreshTokenDurationDays;

    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenService(UserRepository userRepository, UserDetailsService userDetailsService, RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.userDetailsService = userDetailsService;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    //refresh-------------------------------------------------------

    public String createRefreshToken(Long userId) {
        deleteRefreshTokenByUserId(userId);
        RefreshToken token = new RefreshToken();
        token.setUser(userRepository.findById(userId).get());
        token.setExpiryDate(Date.from(Instant.now().plus(refreshTokenDurationDays, ChronoUnit.DAYS)));
        token.setToken(UUID.randomUUID().toString());
        token = refreshTokenRepository.save(token);

        return token.getToken();
    }

    public RefreshToken verifyExpirationOfRefreshToken(RefreshToken token) {
        if (token.getExpiryDate().before(new Date())) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    public RefreshTokenResponse replaceRefreshToken(String requestRefreshToken) {
        RefreshToken refreshToken = findRefreshTokenByToken(requestRefreshToken).orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                "Refresh token is not in database!"));
        refreshToken = verifyExpirationOfRefreshToken(refreshToken);
        User user = refreshToken.getUser();
        String accessToken = createAccessToken(user.getUsername(), user.getRoles());
        return new RefreshTokenResponse(accessToken, refreshToken.getToken());
    }

    public Optional<RefreshToken> findRefreshTokenByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public void deleteRefreshTokenByUserId(Long userId) {
        refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }

    //access-------------------------------------------------------

    public String createAccessToken(String username, List<Role> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", getRoleNames(roles));
        Date now = new Date();
//        Date validity = new Date(now.getTime() + accessTokenDurationMs * 1000);
        Date validity = Date.from(Instant.now().plus(accessTokenDurationMins, ChronoUnit.MINUTES));
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public boolean verifyExpirationOfAccessToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return !claimsJws.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtAuthenticationException("Jwt token is expired or invalid", HttpStatus.UNAUTHORIZED);
        }
    }

    public String resolveAccessTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer_")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsernameFromAccessToken(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsernameFromAccessToken(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    //support methods-------------------------------------------------------

    private List<String> getRoleNames(List<Role> userRoles) {
        List<String> result = new ArrayList<>();

        userRoles.forEach(role -> {
            result.add(role.getName());
        });

        return result;
    }
}
