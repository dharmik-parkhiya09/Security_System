package com.project.security.service;

import com.project.security.dto.request.LoginRequest;
import com.project.security.dto.request.RegisterRequest;
import com.project.security.dto.response.LoginResponse;
import com.project.security.dto.response.RegisterResponse;

import com.project.security.entity.User;
import com.project.security.enums.AuthProviderType;
import com.project.security.enums.RoleType;
import com.project.security.exception.UserNameAlreadyExistException;
import com.project.security.repository.UserRepo;
import com.project.security.security.jwt.JwtTokenProvider;
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

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    public RegisterResponse signup(RegisterRequest signupRequestDto) {
        User user = signUpInternal(signupRequestDto, AuthProviderType.EMAIL, null);
        return new RegisterResponse(user.getId(), user.getUsername());
    }

    public LoginResponse login(LoginRequest loginRequestDto) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDto.getUsername(),
                            loginRequestDto.getPassword()
                    )
            );
        } catch (Exception e) {
            throw e;
        }

        String username = authentication.getName();
        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken = jwtTokenProvider.generateToken(user);

        var refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new LoginResponse(accessToken, refreshToken.getToken(), "Bearer", user.getId());
    }

    public User signUpInternal(RegisterRequest registerRequestDto, AuthProviderType authProviderType, String providerId) {
        User user = userRepo.findByUsername(registerRequestDto.getUsername()).orElse(null);
        if (user != null) throw new UserNameAlreadyExistException("Username already exists");

        user = User.builder()
                .username(registerRequestDto.getUsername())
                .providerId(providerId)
                .provider(authProviderType)
                .roles(
                        registerRequestDto.getRoles().isEmpty()
                                ? Set.of(RoleType.USER)
                                : registerRequestDto.getRoles()
                )
                .createdAt(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")))
                .build();

        if (authProviderType == AuthProviderType.EMAIL) {
            user.setPassword(passwordEncoder.encode(registerRequestDto.getPassword()));
        }

        return userRepo.save(user);
    }

}