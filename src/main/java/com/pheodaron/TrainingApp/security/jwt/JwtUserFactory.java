package com.pheodaron.TrainingApp.security.jwt;

import com.pheodaron.TrainingApp.enums.Status;
import com.pheodaron.TrainingApp.model.Role;
import com.pheodaron.TrainingApp.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.SimpleTimeZone;
import java.util.stream.Collectors;

public final class JwtUserFactory {

    public JwtUserFactory() {
    }

    public static JwtUser create(User user) {
        return new JwtUser(
                user.getId(),
                user.getUsername(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getPassword(),
                mapToGrantedAuthority(user.getRoles()),
                user.getStatus().equals(Status.ACTIVE),
                user.getUpdated()
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthority(List<Role> userRoles) {
        return userRoles.stream()
                .map(role ->
                            new SimpleGrantedAuthority(role.getName())
                        ).collect(Collectors.toList());
    }
}
