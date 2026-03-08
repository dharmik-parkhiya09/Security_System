package com.project.security.service;

import com.project.security.dto.request.LoginRequest;
import com.project.security.dto.request.RegisterRequest;
import com.project.security.dto.request.ResetPasswordRequest;
import com.project.security.dto.response.LoginResponse;
import com.project.security.dto.response.RegisterResponse;
import com.project.security.entity.PasswordResetToken;
import com.project.security.entity.User;
import com.project.security.enums.AuthProviderType;
import com.project.security.enums.RoleType;
import com.project.security.exception.UserNameAlreadyExistException;
import com.project.security.repository.PasswordResetTokenRepo;
import com.project.security.repository.UserRepo;
import com.project.security.security.jwt.JwtTokenProvider;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetTokenRepo passwordResetTokenRepo;
    private final EmailService emailService;

    private static final int RESET_TOKEN_EXPIRY_MINUTES = 5;

    public RegisterResponse signup(RegisterRequest request) {
        User user = signUpInternal(request, AuthProviderType.EMAIL, null);
        return new RegisterResponse(user.getId(), user.getUsername());
    }

    public User signUpInternal(RegisterRequest request,
                               AuthProviderType providerType,
                               String providerId) {

        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            throw new UserNameAlreadyExistException("Username already exists");
        }

        if (userRepo.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .provider(providerType)
                .providerId(providerId)
                .roles(Set.of(RoleType.USER))
                .createdAt(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")))
                .build();

        if (providerType == AuthProviderType.EMAIL) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        return userRepo.save(user);
    }

    public LoginResponse login(LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        String username = authentication.getName();

        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken = jwtTokenProvider.generateToken(user);

        var refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new LoginResponse(
                accessToken,
                refreshToken.getToken(),
                "Bearer",
                user.getId()
        );
    }

    @Transactional
    public void forgotPassword(String email) throws MessagingException {

        if (email == null || email.isBlank()) {
            throw new RuntimeException("Email is required");
        }

        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        passwordResetTokenRepo.deleteByUser(user);

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken =
                PasswordResetToken.builder()
                        .token(token)
                        .user(user)
                        .expiryDate(LocalDateTime.now().plusMinutes(RESET_TOKEN_EXPIRY_MINUTES))
                        .build();

        passwordResetTokenRepo.save(resetToken);

        emailService.sendResetPasswordEmail(user, token);
    }

    public void resetPassword(ResetPasswordRequest request) {

        PasswordResetToken token = passwordResetTokenRepo
                .findByToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token expired");
        }

        User user = token.getUser();

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        userRepo.save(user);

        passwordResetTokenRepo.delete(token);
    }
}