package com.aiinterview.interviewai.config;

import com.aiinterview.interviewai.entity.User;
import com.aiinterview.interviewai.filter.JwtFilter;
import com.aiinterview.interviewai.security.CustomUserDetailsService;
import com.aiinterview.interviewai.serviceimpl.CustomOAuth2UserServiceImpl;
import com.aiinterview.interviewai.serviceimpl.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtFilter jwtFilter;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final CustomOAuth2UserServiceImpl oAuth2UserService;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())

                .sessionManagement(session ->
                        // IMPORTANT: OAuth2 needs a session briefly during the redirect flow,
                        // but we keep it IF_REQUIRED so Spring doesn't break the OAuth2 callback.
                        // JWTs are still stateless for all API calls.
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                .authorizeHttpRequests(auth -> auth
                        // ── Public auth endpoints ──────────────────────────────────────
                        .requestMatchers(
                                "/api/v1/auth/**",   // register, login, OTP, forgot-password
                                "/oauth2/**",        // Spring's internal OAuth2 initiation
                                "/login/oauth2/**"   // Spring's OAuth2 callback handler
                        ).permitAll()

                        // ── Role-protected endpoints ───────────────────────────────────
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/interviewer/**").hasRole("INTERVIEWER")
                        .requestMatchers("/api/v1/interviewee/**").hasRole("INTERVIEWEE")

                        .anyRequest().authenticated()
                )

                // ── OAuth2 Login (Google + GitHub) ────────────────────────────────────
                .oauth2Login(oauth -> oauth
                        // Spring uses /oauth2/authorization/{provider} to start the flow
                        .authorizationEndpoint(ep ->
                                ep.baseUri("/oauth2/authorization")
                        )
                        // Spring's default callback URI — must match what's registered
                        // in Google/GitHub developer console:
                        //   http://localhost:8080/login/oauth2/code/google
                        //   http://localhost:8080/login/oauth2/code/github
                        .redirectionEndpoint(ep ->
                                ep.baseUri("/login/oauth2/code/*")
                        )
                        .userInfoEndpoint(userInfo ->
                                userInfo.userService(oAuth2UserService)
                        )
                        .successHandler(oAuth2SuccessHandler)
                )

                .authenticationProvider(authenticationProvider(customUserDetailsService))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http)
//            throws Exception {
//
//        return http
//                .csrf(AbstractHttpConfigurer::disable)
//
//                .cors(Customizer.withDefaults())
//
//                .sessionManagement(session ->
//                        session.sessionCreationPolicy(
//                                SessionCreationPolicy.STATELESS
//                        )
//                )
//
//                .authorizeHttpRequests(auth -> auth
//
//                        .requestMatchers(
//                                "/api/v1/auth/**",
//                                "/oauth2/**",
//                                "/login/oauth2/**",
//                                "/api/v1/auth/oauth2/**"
//                        ).permitAll()
//
//                        .anyRequest()
//                        .authenticated()
//                )
//
//                .oauth2Login(oauth -> oauth
//                        .userInfoEndpoint(userInfo ->
//                                userInfo.userService(oAuth2UserService)
//                        )
//                        .successHandler(oAuth2SuccessHandler)
//                )
//
//                .authenticationProvider(
//                        authenticationProvider(customUserDetailsService)
//                )
//
//                .addFilterBefore(
//                        jwtFilter,
//                        UsernamePasswordAuthenticationFilter.class
//                )
//
//                .build();
//    }


//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        return http
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(auth->
//                        auth.requestMatchers("/api/v1/auth/**","/api/v1/public/**")
//                        .permitAll()
//                                .anyRequest()
//                                .authenticated()
//                        )
//                .sessionManagement(session->
//                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .authenticationProvider(authenticationProvider(customUserDetailsService))
//                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
//                .oauth2Login(oauth -> oauth
//                .userInfoEndpoint(user -> user.userService(oAuth2UserService))
//                .successHandler(oAuth2SuccessHandler)
//        )
//                .build();
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailsService customUserDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of(
                "http://localhost:5173",
                "http://localhost:3000"
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//
//        CorsConfiguration configuration =
//                new CorsConfiguration();
//
//        configuration.setAllowedOrigins(
//                List.of("http://localhost:5173")
//        );
//
//        configuration.setAllowedMethods(
//                List.of("*")
//        );
//
//        configuration.setAllowedHeaders(
//                List.of("*")
//        );
//
//        configuration.setAllowCredentials(true);
//
//        UrlBasedCorsConfigurationSource source =
//                new UrlBasedCorsConfigurationSource();
//
//        source.registerCorsConfiguration(
//                "/**",
//                configuration
//        );
//
//        return source;
//    }
}
