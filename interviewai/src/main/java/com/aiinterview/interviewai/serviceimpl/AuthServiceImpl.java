package com.aiinterview.interviewai.serviceimpl;

import com.aiinterview.interviewai.dto.*;
import com.aiinterview.interviewai.entity.OtpType;
import com.aiinterview.interviewai.entity.Role;
import com.aiinterview.interviewai.entity.User;
import com.aiinterview.interviewai.exception.*;
import com.aiinterview.interviewai.repository.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements com.aiinterview.interviewai.service.AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final AuthenticationManager authenticationManager;
    private final OtpService otpService;
    private final EmailService emailService;


    @Override
    public ApiResponse<RegisterResponse> register(RegisterRequestDto registerRequest) throws MessagingException {

        if(userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new AlreadyExistsException("user with this email: "+registerRequest.getEmail()+" already exists");
        }

        if(userRepository.existsByUserName(registerRequest.getUserName())) {
            throw new AlreadyExistsException("user with this username already exists");
        }

        if(!registerRequest.isPasswordMatching()) {
            throw new PasswordNotMatchException("password does not match confirm password");
        }

        User user = modelMapper.map(registerRequest, User.class);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setVerified(false);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        user.setActive(true);

        if(user.getRole()==null){
            user.setRole(Role.INTERVIEWEE);
        }

        User savedUser = userRepository.save(user);

//        otpService.generateOtp(savedUser.getEmail(), OtpType.REGISTRATION);
        emailService.sendVerificationEmail(savedUser);

        RegisterResponse registerResponse=RegisterResponse.builder()
                .id(savedUser.getId())
                .userName(savedUser.getUserName())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .requireVerification(true)
                .build();


        return ApiResponse.<RegisterResponse>builder()
                .message("User registered successfully, Please verify your email with the otp sent to you email")
                .data(registerResponse)
                .success(true)
                .statusCode(HttpStatus.CREATED.value())
                .time(LocalDateTime.now())
                .build();

    }

    @Override
    public ApiResponse<LoginResponse> login(
            LoginRequestDto loginRequest
    ) throws AccountNotVerifiedException {

        User user =
                userRepository.findByEmail(loginRequest.getEmail());

        if(user == null){
            throw new InvalidCredentialsException(
                    "Invalid email or password"
            );
        }

        if(!user.isVerified()){
            throw new AccountNotVerifiedException(
                    "Please verify your account"
            );
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        String accessToken =
                jwtService.generateAccessToken(user);

        LoginResponse response =
                LoginResponse.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .role(user.getRole())
                        .userName(user.getUserName())
                        .jwt(accessToken)
                        .build();

        return ApiResponse.<LoginResponse>builder()
                .success(true)
                .message("Login successful")
                .data(response)
                .statusCode(200)
                .build();
    }

    @Override
    public ApiResponse<?> verifyUserWithOtp(VerifyOtpRequest verifyOtpRequest) throws MessagingException, OtpNotValidException {
        User user = userRepository.findByEmail(verifyOtpRequest.getEmail());

        if (user == null) {
            throw new UserNotFoundException("User not found with email: " + verifyOtpRequest.getEmail());
        }

        if (user.isVerified()) {
            return ApiResponse.builder()
                    .success(false)
                    .message("Account is already verified")
                    .data(null)
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .time(LocalDateTime.now())
                    .build();
        }

        boolean isValid = otpService.validateOtp(user.getEmail(), OtpType.REGISTRATION, verifyOtpRequest.getOtp());

        if (!isValid) {
            throw new OtpNotValidException("Your OTP is incorrect or expired. Please request a new one.");
        }

        user.setVerified(true);
        user.setUpdatedAt(LocalDateTime.now());
        User savedUser = userRepository.save(user);

        RegisterResponse response = RegisterResponse.builder()
                .id(savedUser.getId())
                .userName(savedUser.getUserName())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .requireVerification(false)
                .build();

        return ApiResponse.builder()
                .success(true)
                .message("Verification successful! You can now login.")
                .data(response)
                .statusCode(HttpStatus.OK.value())
                .time(LocalDateTime.now())
                .build();
    }

    @Override
    public ApiResponse<?> resetPasswordWithOtp(@Valid ForgotPasswordRequest forgotPasswordRequest)
            throws MessagingException {

        User user = userRepository.findByEmail(forgotPasswordRequest.getEmail());

        if (user == null) {
            throw new UserNotFoundException("User not found with email: " + forgotPasswordRequest.getEmail());
        }

        // Check if account is active
        if (!user.isActive()) {
            throw new RuntimeException("Your account is deactivated. Please contact support.");
        }

        if(user.getRole()==Role.ADMIN){
            throw new AuthorizationDeniedException("you don't have enough rights to perform this operation.");
        }

        // Rate limiting - Check if user can request OTP
        if (!otpService.canRequestOtp(user.getEmail(), OtpType.FORGOT_PASSWORD)) {
            throw new RuntimeException("Too many OTP requests. Please try again after 15 minutes.");
        }

        // Send FORGOT PASSWORD email (NOT verification email)
        emailService.sendForgotPasswordOtp(user);
        log.info("send mail to "+user.getEmail());
        otpService.incrementOtpRequestCount(user.getEmail(), OtpType.FORGOT_PASSWORD);

        // Generate a reset token for additional security
//        String resetToken = UUID.randomUUID().toString();
//        user.setResetToken(resetToken);
//        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(30));
        userRepository.save(user);

        Map<String, Object> response = Map.of(
                "email", user.getEmail()
        );

        return ApiResponse.builder()
                .success(true)
                .message("OTP sent to your email. Please verify to reset password.")
                .data(response)
                .statusCode(HttpStatus.OK.value())
                .time(LocalDateTime.now())
                .build();
    }


    @Override
    public ApiResponse<?> verifyOtpForgotPassword(@Valid VerifyOtpRequest request)
            throws OtpNotValidException {

        boolean isValid = otpService.validateOtp(request.getEmail(), OtpType.FORGOT_PASSWORD, request.getOtp());

        if (!isValid) {
            throw new OtpNotValidException("Your OTP is incorrect or expired. Please request a new one.");
        }

        otpService.markOtpVerified(request.getEmail(), OtpType.FORGOT_PASSWORD);

        return ApiResponse.builder()
                .success(true)
                .message("OTP verified successfully. You can now reset your password.")
                .data(null)
                .statusCode(HttpStatus.OK.value())
                .time(LocalDateTime.now())
                .build();
    }


    @Override
    public ApiResponse<?> updatePassword(@Valid ResetPasswordDto resetPasswordDto) {

        if (!resetPasswordDto.isMatching()) {
            throw new PasswordNotMatchException("Password and confirm password do not match");
        }

        User user = userRepository.findByEmail(resetPasswordDto.getEmail());
        if (user == null) {
            throw new UserNotFoundException("User not found with email: " + resetPasswordDto.getEmail());
        }

        if (!otpService.isOtpVerified(resetPasswordDto.getEmail(), OtpType.FORGOT_PASSWORD)) {
            throw new RuntimeException("Unauthorized: Please complete OTP verification first.");
        }



        if (passwordEncoder.matches(resetPasswordDto.getPassword(), user.getPassword())) {
            throw new RuntimeException("New password cannot be the same as your current password");
        }

        user.setPassword(passwordEncoder.encode(resetPasswordDto.getPassword()));
        user.setUpdatedAt(LocalDateTime.now());
//        user.setResetToken(null);
//        user.setResetTokenExpiry(null);
        userRepository.save(user);

        otpService.clearVerifiedOtp(resetPasswordDto.getEmail(), OtpType.FORGOT_PASSWORD);
        otpService.invalidateOtp(resetPasswordDto.getEmail(), OtpType.FORGOT_PASSWORD);

        return ApiResponse.builder()
                .success(true)
                .message("Password updated successfully. Please login with your new password.")
                .data(null)
                .statusCode(HttpStatus.OK.value())
                .time(LocalDateTime.now())
                .build();
    }

    @Override
    public ApiResponse<?> resendOtp(ResendOtpRequest resendOtpRequest) throws MessagingException {

        String email = resendOtpRequest.getEmail();
        OtpType type = resendOtpRequest.getType();

        log.info("Resend OTP request for email: {}, type: {}", email, type);

        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UserNotFoundException("User not found with email: " + email);
        }

        switch (type) {
            case REGISTRATION:
                return resendRegistrationOtp(user);

            case FORGOT_PASSWORD:
                return resendForgotPasswordOtp(user);


            default:
                throw new RuntimeException("Unsupported OTP type: " + type);
        }
    }

    private ApiResponse<?> resendRegistrationOtp(User user) throws MessagingException {

        if (user.isVerified()) {
            return ApiResponse.builder()
                    .success(false)
                    .message("Account is already verified. Please login.")
                    .data(null)
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .time(LocalDateTime.now())
                    .build();
        }

        if (!otpService.canRequestOtp(user.getEmail(), OtpType.REGISTRATION)) {
            long remainingSeconds = otpService.getRemainingBlockTime(user.getEmail(), OtpType.REGISTRATION);
            throw new RuntimeException("Too many OTP requests. Please try again after " + remainingSeconds + " seconds.");
        }

        otpService.invalidateOtp(user.getEmail(), OtpType.REGISTRATION);
        otpService.clearVerifiedOtp(user.getEmail(), OtpType.REGISTRATION);

        emailService.sendVerificationEmail(user);
        otpService.incrementOtpRequestCount(user.getEmail(), OtpType.REGISTRATION);

        Map<String, Object> response = Map.of(
                "email", user.getEmail(),
                "type", "REGISTRATION",
                "message", "New verification OTP sent successfully."
        );

        return ApiResponse.builder()
                .success(true)
                .message("Verification OTP resent successfully. Please check your email.")
                .data(response)
                .statusCode(HttpStatus.OK.value())
                .time(LocalDateTime.now())
                .build();
    }


    private ApiResponse<?> resendForgotPasswordOtp(User user) throws MessagingException {

        if (!user.isActive()) {
            throw new RuntimeException("Your account is deactivated. Please contact support.");
        }

        if (!otpService.canRequestOtp(user.getEmail(), OtpType.FORGOT_PASSWORD)) {
            long remainingSeconds = otpService.getRemainingBlockTime(user.getEmail(), OtpType.FORGOT_PASSWORD);
            throw new RuntimeException("Too many OTP requests. Please try again after " + remainingSeconds + " seconds.");
        }

        otpService.invalidateOtp(user.getEmail(), OtpType.FORGOT_PASSWORD);
        otpService.clearVerifiedOtp(user.getEmail(), OtpType.FORGOT_PASSWORD);

//        String newResetToken = UUID.randomUUID().toString();
//        user.setResetToken(newResetToken);
//        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(30));
        userRepository.save(user);

        emailService.sendForgotPasswordOtp(user);
        otpService.incrementOtpRequestCount(user.getEmail(), OtpType.FORGOT_PASSWORD);

        Map<String, Object> response = Map.of(
                "email", user.getEmail(),
//                "resetToken", newResetToken,
//                "expiresInMinutes", 30,
                "type", "FORGOT_PASSWORD",
                "message", "New password reset OTP sent."
        );

        return ApiResponse.builder()
                .success(true)
                .message("Password reset OTP resent successfully. Please check your email.")
                .data(response)
                .statusCode(HttpStatus.OK.value())
                .time(LocalDateTime.now())
                .build();
    }
}

