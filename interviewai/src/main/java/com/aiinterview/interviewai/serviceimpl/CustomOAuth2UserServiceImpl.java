package com.aiinterview.interviewai.serviceimpl;

import com.aiinterview.interviewai.entity.AuthProvider;
import com.aiinterview.interviewai.entity.Role;
import com.aiinterview.interviewai.entity.User;
import com.aiinterview.interviewai.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserServiceImpl extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(request);

        String registrationId = request.getClientRegistration()
                .getRegistrationId()
                .toUpperCase(); // "GOOGLE" or "GITHUB"

        AuthProvider provider;
        try {
            provider = AuthProvider.valueOf(registrationId);
        } catch (IllegalArgumentException e) {
            throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        }

        String email     = extractEmail(oAuth2User, provider);
        String fullName  = extractFullName(oAuth2User, provider);
        String avatarUrl = extractAvatarUrl(oAuth2User, provider);
        String providerId = extractProviderId(oAuth2User, provider);

        if (email == null || email.isBlank()) {
            log.error("Email not returned by {} OAuth2 provider", registrationId);
            throw new OAuth2AuthenticationException(
                    "Email not found from " + registrationId + " provider. " +
                            "Please ensure your email is public in your account settings."
            );
        }

        log.info("OAuth2 login attempt — provider: {}, email: {}", registrationId, email);

        User user = userRepository.findByEmail(email);

        if (user == null) {
            // First time — register new OAuth2 user
            String username = email.split("@")[0];

            user = User.builder()
                    .email(email)
                    .userName(username)
                    .fullName(fullName)
                    .profileImageUrl(avatarUrl)
                    .providerId(providerId)
                    .authProvider(provider)
                    .role(Role.INTERVIEWEE)
                    .isVerified(true)
                    .isActive(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();

            userRepository.save(user);
            log.info("New OAuth2 user registered: {} via {}", email, registrationId);

        } else {
            // Returning user — update profile fields in case they changed upstream
            user.setFullName(fullName);
            user.setProfileImageUrl(avatarUrl);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            log.info("Returning OAuth2 user: {} via {}", email, registrationId);
        }

        return oAuth2User;
    }


    private String extractEmail(OAuth2User user, AuthProvider provider) {
        switch (provider) {
            case GOOGLE:
                return user.getAttribute("email");

            case GITHUB:
                String email = user.getAttribute("email");
                if (email == null) {
                    // Fallback: build a noreply address from the GitHub username
                    String login = user.getAttribute("login");
                    Object id    = user.getAttribute("id");
                    if (login != null && id != null) {
                        email = id + "+" + login + "@users.noreply.github.com";
                        log.warn("GitHub email was null; using noreply address: {}", email);
                    }
                }
                return email;

            default:
                return user.getAttribute("email");
        }
    }

    private String extractFullName(OAuth2User user, AuthProvider provider) {
        switch (provider) {
            case GOOGLE:
                return user.getAttribute("name");

            case GITHUB:
                String name = user.getAttribute("name");
                if (name == null || name.isBlank()) {
                    name = user.getAttribute("login"); // GitHub username as fallback
                }
                return name;

            default:
                return user.getAttribute("name");
        }
    }

    private String extractAvatarUrl(OAuth2User user, AuthProvider provider) {
        switch (provider) {
            case GOOGLE:
                return user.getAttribute("picture");

            case GITHUB:
                return user.getAttribute("avatar_url");

            default:
                return null;
        }
    }

    private String extractProviderId(OAuth2User user, AuthProvider provider) {
        switch (provider) {
            case GOOGLE:
                return user.getAttribute("sub");

            case GITHUB:
                Object id = user.getAttribute("id");
                return id != null ? String.valueOf(id) : null;

            default:
                return null;
        }
    }
}