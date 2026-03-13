package com.project.security.controller;

import com.project.security.dto.request.*;
import com.project.security.dto.response.AuthResponse;
import com.project.security.dto.response.LoginResponse;
import com.project.security.dto.response.RegisterResponse;
import com.project.security.entity.RefreshToken;
import com.project.security.entity.User;
import com.project.security.entity.VerificationToken;
import com.project.security.repository.RefreshTokenRepository;
import com.project.security.repository.UserRepo;
import com.project.security.repository.VerificationTokenRepository;
import com.project.security.security.jwt.JwtTokenProvider;
import com.project.security.service.AuthService;
import com.project.security.service.RefreshTokenService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final UserRepo userRepo;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.signup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest httpRequest) throws MessagingException {
        log.info("LOGIN HIT: {}", request.getUsername());
        LoginResponse response = authService.login(request, httpRequest);
        log.info("LOGIN RESPONSE: {}", response);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/verify")
    public void verify(@RequestParam String token,
                       HttpServletResponse response) throws IOException {

        VerificationToken vt = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid or expired verification token"));

        if (vt.getExpiryDate().isBefore(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")))) {
            throw new RuntimeException("Verification link has expired. Please request a new one.");
        }

        User user = vt.getUser();
        user.setVerified(true);
        userRepo.save(user);

        verificationTokenRepository.delete(vt);

        response.sendRedirect("http://localhost:8083/index.html?verified=true");
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshRequest request) {

        RefreshToken refreshToken = refreshTokenService.verifyExpiration(request.getRefreshToken());

        String newAccessToken = jwtTokenProvider.generateToken(refreshToken.getUser());

        return ResponseEntity.ok(
                new AuthResponse(
                        newAccessToken,
                        request.getRefreshToken(),
                        "Bearer"
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody LogoutRequest request) {

        refreshTokenRepository.deleteByToken(request.getRefreshToken());

        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(
            @RequestBody ForgotPasswordRequest request)
            throws MessagingException {

        authService.forgotPassword(request.getEmail());

        return ResponseEntity.ok("Password reset email sent, Please go to mail and click Reset password");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @RequestBody ResetPasswordRequest request){

        authService.resetPassword(request);

        return ResponseEntity.ok("Password updated successfully");
    }

}