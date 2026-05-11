package com.aiinterview.interviewai.controller;

import com.aiinterview.interviewai.dto.*;
import com.aiinterview.interviewai.exception.AccountNotVerifiedException;
import com.aiinterview.interviewai.exception.OtpNotValidException;
import com.aiinterview.interviewai.service.AuthService;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    /**
     * User Registration
     * POST /api/v1/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse> registerUser(@Valid @RequestBody RegisterRequestDto registerRequest)
            throws MessagingException {
        log.info("Registration request for email: {}", registerRequest.getEmail());
        ApiResponse apiResponse = authService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }

    /**
     * User Login
     * POST /api/v1/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(@Valid @RequestBody LoginRequestDto loginRequest)
            throws AccountNotVerifiedException {
        log.info("Login request for email: {}", loginRequest.getEmail());
        ApiResponse<LoginResponse> response = authService.login(loginRequest);
        return ResponseEntity.ok(response);
    }

    /**
     * Verify OTP for Account Registration
     * POST /api/v1/auth/verify-otp
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse> verifyAccountUsingOtp(@Valid @RequestBody VerifyOtpRequest verifyOtpRequest)
            throws MessagingException, OtpNotValidException {
        log.info("OTP verification request for email: {}", verifyOtpRequest.getEmail());
        ApiResponse response = authService.verifyUserWithOtp(verifyOtpRequest);
        return ResponseEntity.ok(response);
    }

    // ==================== FORGOT PASSWORD FLOW ====================

    /**
     * Step 1: Forgot Password - Send OTP to email
     * POST /api/v1/auth/forgot-password
     *
     * Request Body:
     * {
     *     "email": "user@example.com"
     * }
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest)
            throws MessagingException {
        log.info("Forgot password request for email: {}", forgotPasswordRequest.getEmail());
        ApiResponse response = authService.resetPasswordWithOtp(forgotPasswordRequest);
        return ResponseEntity.ok(response);
    }

    /**
     * Step 2: Verify OTP for Forgot Password
     * POST /api/v1/auth/verify-forgot-password-otp
     *
     * Request Body:
     * {
     *     "email": "user@example.com",
     *     "otp": "123456"
     * }
     */
    @PostMapping("/verify-forgot-password-otp")
    public ResponseEntity<ApiResponse> verifyForgotPasswordOtp(@Valid @RequestBody VerifyOtpRequest request)
            throws OtpNotValidException {
        log.info("Forgot password OTP verification for email: {}", request.getEmail());
        ApiResponse response = authService.verifyOtpForgotPassword(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Step 3: Reset Password after OTP verification
     * POST /api/v1/auth/reset-password
     *
     * Request Body:
     * {
     *     "email": "user@example.com",
     *     "password": "NewSecurePass123!",
     *     "confirmPassword": "NewSecurePass123!",
     *     "resetToken": "optional-uuid-from-step-1"
     * }
     */
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(@Valid @RequestBody ResetPasswordDto resetPasswordDto) {
        log.info("Password reset request for email: {}", resetPasswordDto.getEmail());
        ApiResponse response = authService.updatePassword(resetPasswordDto);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse> resendOtp(@Valid @RequestBody ResendOtpRequest resendOtpRequest)
            throws MessagingException {
        log.info("Resend OTP request for email: {}, type: {}",
                resendOtpRequest.getEmail(), resendOtpRequest.getType());
        ApiResponse response = authService.resendOtp(resendOtpRequest);
        return ResponseEntity.ok(response);
    }

}