package com.pheodaron.TrainingApp.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pheodaron.TrainingApp.errors.ErrorResponse;
import com.pheodaron.TrainingApp.exceptions.JwtAuthenticationException;
import com.pheodaron.TrainingApp.service.impl.TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtTokenFilter extends GenericFilterBean {
    private final TokenService tokenService;

    public JwtTokenFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String token = tokenService.resolveAccessTokenFromRequest((HttpServletRequest) servletRequest);
        try {
            if (token != null && tokenService.verifyExpirationOfAccessToken(token)) {
                Authentication authentication = tokenService.getAuthentication(token);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (JwtAuthenticationException e) {
            SecurityContextHolder.clearContext();
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED, "JWT token is expired or invalid");
            byte[] responseToSend = restResponseBytes(errorResponse);
            ((HttpServletResponse) servletResponse).setHeader("Content-Type", "application/json");
            ((HttpServletResponse) servletResponse).setStatus(401);
            servletResponse.getOutputStream().write(responseToSend);
            return;
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private byte[] restResponseBytes(ErrorResponse eErrorResponse) throws IOException {
        String serialized = new ObjectMapper().writeValueAsString(eErrorResponse);
        return serialized.getBytes();
    }
}
