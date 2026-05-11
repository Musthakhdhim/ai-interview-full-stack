package com.aiinterview.interviewai.serviceimpl;

import com.aiinterview.interviewai.entity.User;
import com.aiinterview.interviewai.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;

        // ── Get email (works for both Google and GitHub) ──────────────────────
        String email = token.getPrincipal().getAttribute("email");

        // GitHub noreply fallback (mirrors CustomOAuth2UserServiceImpl logic)
        if (email == null) {
            String login = token.getPrincipal().getAttribute("login");
            Object id    = token.getPrincipal().getAttribute("id");
            if (login != null && id != null) {
                email = id + "+" + login + "@users.noreply.github.com";
            }
        }

        if (email == null) {
            log.error("Cannot determine email from OAuth2 token — aborting redirect");
            response.sendRedirect(frontendUrl + "/login?error=email_missing");
            return;
        }

        // ── Load saved user ───────────────────────────────────────────────────
        User user = userRepository.findByEmail(email);
        if (user == null) {
            log.error("OAuth2 success but user not found in DB for email: {}", email);
            response.sendRedirect(frontendUrl + "/login?error=user_not_found");
            return;
        }

        // ── Generate tokens ───────────────────────────────────────────────────
        String accessToken  = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // ── Build redirect URL based on role ──────────────────────────────────
        String dashboardPath = switch (user.getRole()) {
            case ADMIN       -> "/admin/dashboard";
            case INTERVIEWER -> "/interviewer/dashboard";
            case INTERVIEWEE -> "/interviewee/dashboard";
        };

        /*
         * Redirect to /oauth2/redirect on the frontend.
         * The frontend reads the query params, stores the tokens,
         * then navigates the user to their dashboard.
         *
         * URL pattern:
         *   http://localhost:5173/oauth2/redirect
         *     ?token=<accessToken>
         *     &refreshToken=<refreshToken>
         *     &role=INTERVIEWEE
         *     &redirect=/interviewee/dashboard
         */
//        String redirectUrl = frontendUrl + "/oauth2/redirect"
//                + "?token="        + URLEncoder.encode(accessToken,  StandardCharsets.UTF_8)
//                + "&refreshToken=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)
//                + "&role="         + URLEncoder.encode(user.getRole().name(), StandardCharsets.UTF_8)
//                + "&redirect="     + URLEncoder.encode(dashboardPath, StandardCharsets.UTF_8);

        String email1 = user.getEmail();
        String userName = user.getUserName(); // or user.getFullName()
        String redirectUrl = frontendUrl + "/oauth2/redirect"
                + "?token=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8)
                + "&refreshToken=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8)
                + "&role=" + URLEncoder.encode(user.getRole().name(), StandardCharsets.UTF_8)
                + "&email=" + URLEncoder.encode(email1, StandardCharsets.UTF_8)
                + "&name=" + URLEncoder.encode(userName, StandardCharsets.UTF_8)
                + "&redirect=" + URLEncoder.encode(dashboardPath, StandardCharsets.UTF_8);

        log.info("OAuth2 success for {} (role: {}), redirecting to {}",
                email, user.getRole(), dashboardPath);

        response.sendRedirect(redirectUrl);
    }
}












//package com.aiinterview.interviewai.serviceimpl;
//
//import com.aiinterview.interviewai.entity.User;
//import com.aiinterview.interviewai.repository.UserRepository;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.ResponseCookie;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//import java.time.Duration;
//
//@Component
//@RequiredArgsConstructor
//public class OAuth2SuccessHandler
//        implements AuthenticationSuccessHandler {
//
//    private final JwtService jwtService;
//    private final UserRepository userRepository;
//
//    @Override
//    public void onAuthenticationSuccess(
//            HttpServletRequest request,
//            HttpServletResponse response,
//            Authentication authentication
//    ) throws IOException {
//
//        OAuth2AuthenticationToken token =
//                (OAuth2AuthenticationToken) authentication;
//
//        String email =
//                token.getPrincipal().getAttribute("email");
//
//        User user = userRepository.findByEmail(email);
//
//        String accessToken =
//                jwtService.generateAccessToken(user);
//
//        String refreshToken =
//                jwtService.generateRefreshToken(user);
//
//        ResponseCookie cookie =
//                ResponseCookie.from("refreshToken", refreshToken)
//                        .httpOnly(true)
//                        .secure(false)
//                        .sameSite("Lax")
//                        .path("/")
//                        .maxAge(Duration.ofDays(7))
//                        .build();
//
//        response.addHeader(
//                HttpHeaders.SET_COOKIE,
//                cookie.toString()
//        );
//
//        response.sendRedirect(
////                "http://localhost:5173/oauth-success?token="
////                        + accessToken
//                "http://localhost:5173//interviewee"
//        );
//    }
//}