package com.aiinterview.interviewai.security;

import com.aiinterview.interviewai.entity.User;
import com.aiinterview.interviewai.exception.UserNotFoundException;
import com.aiinterview.interviewai.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);

        if (user == null) {
            user = userRepository.findByUserName(username);
        }

        if (user == null) {
            log.error("user not found in the database: {}", username);
            throw new UserNotFoundException("user with " + username + " not found");
        }
        return new CustomUserDetails(user);
    }
}
