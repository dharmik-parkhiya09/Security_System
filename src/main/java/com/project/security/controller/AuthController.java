package com.project.security.controller;

import com.project.security.dto.request.LoginRequest;
import com.project.security.dto.request.LogoutRequest;
import com.project.security.dto.request.RefreshRequest;
import com.project.security.dto.request.RegisterRequest;
import com.project.security.dto.response.AuthResponse;
import com.project.security.dto.response.LoginResponse;
import com.project.security.dto.response.RegisterResponse;
import com.project.security.entity.RefreshToken;
import com.project.security.entity.User;
import com.project.security.repository.RefreshTokenRepository;
import com.project.security.repository.UserRepo;
import com.project.security.security.jwt.JwtTokenProvider;
import com.project.security.service.AuthService;
import com.project.security.service.RefreshTokenService;
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

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.signup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("LOGIN HIT: {}", request.getUsername());
        LoginResponse response = authService.login(request);
        log.info("LOGIN RESPONSE: {}", response);  // ← ADD THIS
        return ResponseEntity.ok(response);
    }

    @GetMapping("/verify")
    public void verify(@RequestParam String token,
                       HttpServletResponse response) throws IOException {

        User user = userRepo.findByVerificationToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (user.getVerificationExpiry().isBefore(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")))) {
            throw new RuntimeException("Token expired");
        }

        user.setVerified(true);
        user.setVerificationToken(null);
        user.setVerificationExpiry(null);
        userRepo.save(user);

        String jwt = jwtTokenProvider.generateToken(user);

        response.sendRedirect(
                "http://localhost:8083/index.html?token=" + jwt
        );
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
}