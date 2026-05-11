package com.aiinterview.interviewai.service;

import com.aiinterview.interviewai.dto.*;
import com.aiinterview.interviewai.exception.AccountNotVerifiedException;
import com.aiinterview.interviewai.exception.OtpNotValidException;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;

public interface AuthService {
    ApiResponse<RegisterResponse> register(RegisterRequestDto registerRequest) throws MessagingException;

    ApiResponse<LoginResponse> login(LoginRequestDto loginRequest) throws AccountNotVerifiedException;

    ApiResponse<?> verifyUserWithOtp(VerifyOtpRequest verifyOtpRequest) throws MessagingException, OtpNotValidException;

    ApiResponse<?> resetPasswordWithOtp(@Valid ForgotPasswordRequest forgotPasswordRequest)
            throws MessagingException;

    ApiResponse<?> verifyOtpForgotPassword(@Valid VerifyOtpRequest request)
            throws OtpNotValidException;

    ApiResponse<?> updatePassword(@Valid ResetPasswordDto resetPasswordDto);

    ApiResponse<?> resendOtp(ResendOtpRequest resendOtpRequest) throws MessagingException;
}
