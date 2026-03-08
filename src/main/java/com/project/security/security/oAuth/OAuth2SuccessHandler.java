package com.project.security.security.oAuth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.security.entity.User;
import com.project.security.enums.AuthProviderType;
import com.project.security.enums.RoleType;
import com.project.security.repository.UserRepo;
import com.project.security.security.jwt.JwtTokenProvider;
import com.project.security.service.EmailService;
import com.project.security.service.RefreshTokenService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepo userRepo;
    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;
    private final EmailService emailService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2AuthenticationToken authToken =
                (OAuth2AuthenticationToken) authentication;

        OAuth2User oAuth2User = authToken.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String providerId = oAuth2User.getAttribute("sub");

        if (email == null) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

        User user = userRepo.findByProviderIdAndProvider(providerId, AuthProviderType.GOOGLE)
                .orElseGet(() -> {
                    return userRepo.findByEmail(email)
                            .orElseGet(() -> {
                                User newUser = new User();
                                newUser.setEmail(email);
                                newUser.setUsername(email);
                                newUser.setProvider(AuthProviderType.GOOGLE);
                                newUser.setProviderId(providerId);
                                newUser.setPassword(UUID.randomUUID().toString());
                                newUser.setCreatedAt(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")));
                                newUser.setRoles(Set.of(RoleType.USER));
                                newUser.setVerified(false);

                                return userRepo.save(newUser);
                            });
                });

        if (!user.isVerified()) {

            String token = UUID.randomUUID().toString();

            user.setVerificationToken(token);
            user.setVerificationExpiry(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")).plusMinutes(15));
            userRepo.save(user);

            try {
                emailService.sendVerificationEmail(user, token);
                log.info("Verification email sent to {}", email);
            } catch (MessagingException e) {
                log.error("Failed to send verification email", e);
                throw new RuntimeException("Email sending failed");
            }

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getWriter(),
                    "Verification email sent. Please verify your account.");
            return;
        }

        String accessToken = jwtTokenProvider.generateToken(user);
        String refreshToken =
                refreshTokenService.createRefreshToken(user.getId()).getToken();


        try {
            emailService.sendLoginAlertEmail(user);
            log.info("Login alert email sent to {}", user.getUsername());
        } catch (MessagingException e) {
            log.warn("Failed to send login alert email", e);
        }

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.sendRedirect(
                "http://localhost:8083/index.html?token=" + accessToken +
                        "&refresh=" + refreshToken
        );

        log.info("User {} logged in successfully via OAuth2", email);
    }
}