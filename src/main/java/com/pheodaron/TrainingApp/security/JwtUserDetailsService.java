package com.pheodaron.TrainingApp.security;

import com.pheodaron.TrainingApp.model.User;
import com.pheodaron.TrainingApp.repository.UserRepository;
import com.pheodaron.TrainingApp.security.jwt.JwtUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("jwtUserDetailService")
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    
    public JwtUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null) {
            throw new UsernameNotFoundException("User with username: " + username + "not found");
        }

        return JwtUser.create(user);
    }
}
