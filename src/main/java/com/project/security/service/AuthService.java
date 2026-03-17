package com.project.security.service;

import com.project.security.dto.request.LoginRequest;
import com.project.security.dto.request.RegisterRequest;
import com.project.security.dto.request.ResetPasswordRequest;
import com.project.security.dto.response.LoginResponse;
import com.project.security.dto.response.RegisterResponse;
import com.project.security.entity.PasswordResetToken;
import com.project.security.entity.User;
import com.project.security.entity.VerificationToken;
import com.project.security.enums.AuthProviderType;
import com.project.security.enums.RoleType;
import com.project.security.exception.UserNameAlreadyExistException;
import com.project.security.repository.PasswordResetTokenRepo;
import com.project.security.repository.UserRepo;
import com.project.security.repository.VerificationTokenRepository;
import com.project.security.security.jwt.JwtTokenProvider;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
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
    private final VerificationTokenRepository verificationTokenRepository;

    private static final int RESET_TOKEN_EXPIRY_MINUTES = 5;

    public RegisterResponse signup(RegisterRequest request) {
        User user = null;
        try {
            user = signUpInternal(request, AuthProviderType.EMAIL, null);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
        return new RegisterResponse(user.getId(), user.getUsername());
    }

    public User signUpInternal(RegisterRequest request,
                               AuthProviderType providerType,
                               String providerId) throws MessagingException {

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
                .verified(false)
                .createdAt(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")))
                .build();

        if (providerType == AuthProviderType.EMAIL) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        } else {
            user.setVerified(true);
        }

        userRepo.save(user);

        if (providerType == AuthProviderType.EMAIL) {
            String token = UUID.randomUUID().toString();

            VerificationToken vt = VerificationToken.builder()
                    .token(token)
                    .user(user)
                    .expiryDate(ZonedDateTime.now().plusMinutes(30))
                    .build();

            verificationTokenRepository.save(vt);
            emailService.sendVerificationEmail(user, token);
        }

        return user;
    }

    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) throws MessagingException {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        String username = authentication.getName();

        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken  = jwtTokenProvider.generateToken(user);
        var    refreshToken = refreshTokenService.createRefreshToken(user.getId());

        // --- Extract real client IP (handles reverse-proxy X-Forwarded-For) ---
        String ip = httpRequest.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = httpRequest.getRemoteAddr();
        } else {
            ip = ip.split(",")[0].trim();
        }

        // --- Resolve IP to city/country, get device label and login time ---
        String location  = resolveLocation(ip);
        String device    = parseDevice(httpRequest.getHeader("User-Agent"));
        String loginTime = ZonedDateTime.now(ZoneId.of("Asia/Kolkata"))
                .format(DateTimeFormatter.ofPattern("dd MMM yyyy, hh:mm a z"));

        // --- Send alert (best-effort — never fail the login if mail fails) ---
        try {
            emailService.sendLoginAlertEmail(user, location, device, loginTime);
        } catch (Exception e) {
            log.warn("Login alert email could not be sent for user {}: {}", username, e.getMessage());
        }

        return new LoginResponse(
                accessToken,
                refreshToken.getToken(),
                "Bearer",
                user.getId()
        );
    }

    /**
     * Calls ip-api.com to resolve an IP address to "City, Region, Country".
     * - Loopback IPs  → "Local network (localhost)"
     * - Private ranges → "Private network"
     * - Any failure    → raw IP string as safe fallback
     */
    private String resolveLocation(String ip) {
        if (ip == null || ip.isBlank()) return "Unknown location";

        // Normalise IPv6: strip brackets and zone-id (e.g. [::1]%0 → ::1)
        ip = ip.replaceAll("[\\[\\]]", "").split("%")[0].trim();

        // Loopback — covers 127.0.0.1, ::1, and all verbose forms like 0:0:0:0:0:0:0:1
        boolean isLoopback = ip.equals("127.0.0.1")
                || ip.equals("::1")
                || ip.equals("0:0:0:0:0:0:0:1")
                || ip.startsWith("0:0:0:0");
        if (isLoopback) return "Local network (localhost)";

        // Private IPv4 ranges
        if (ip.startsWith("10.") || ip.startsWith("192.168.") ||
                ip.matches("172\\.(1[6-9]|2[0-9]|3[01])\\..*")) {
            return "Private network";
        }

        try {
            // Wrap bare IPv6 addresses in brackets so the URL is valid
            String urlIp = ip.contains(":") ? "[" + ip + "]" : ip;
            URL url = new URL("http://ip-api.com/json/" + urlIp + "?fields=status,city,regionName,country");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);

            if (conn.getResponseCode() != 200) {
                log.warn("ip-api.com returned HTTP {} for IP {}", conn.getResponseCode(), ip);
                return ip;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            reader.close();

            String json = sb.toString();
            if (json.contains("\"status\":\"fail\"")) {
                log.warn("ip-api.com failed to resolve IP: {}", ip);
                return ip;
            }

            String city    = extractJsonField(json, "city");
            String region  = extractJsonField(json, "regionName");
            String country = extractJsonField(json, "country");

            StringBuilder loc = new StringBuilder();
            if (!city.isEmpty())   loc.append(city);
            if (!region.isEmpty() && !region.equals(city)) {
                if (loc.length() > 0) loc.append(", ");
                loc.append(region);
            }
            if (!country.isEmpty()) {
                if (loc.length() > 0) loc.append(", ");
                loc.append(country);
            }

            return loc.length() > 0 ? loc.toString() : ip;

        } catch (Exception e) {
            log.warn("Location lookup failed for IP {}: {}", ip, e.getMessage());
            return ip;
        }
    }

    /** Extracts a string value from a flat JSON object without a JSON library. */
    private String extractJsonField(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return "";
        start += search.length();
        int end = json.indexOf("\"", start);
        return end == -1 ? "" : json.substring(start, end);
    }

    /** Converts a raw User-Agent string into a concise "Browser on OS" label. */
    private String parseDevice(String ua) {
        if (ua == null || ua.isBlank()) return "Unknown device";

        String browser;
        String os;

        if      (ua.contains("Edg/"))                               browser = "Microsoft Edge";
        else if (ua.contains("OPR/"))                               browser = "Opera";
        else if (ua.contains("Chrome/"))                            browser = "Chrome";
        else if (ua.contains("Firefox/"))                           browser = "Firefox";
        else if (ua.contains("Safari/") && !ua.contains("Chrome"))  browser = "Safari";
        else if (ua.contains("MSIE") || ua.contains("Trident/"))    browser = "Internet Explorer";
        else                                                         browser = "Unknown browser";

        if      (ua.contains("Windows NT"))                         os = "Windows";
        else if (ua.contains("Mac OS X"))                           os = "macOS";
        else if (ua.contains("Android"))                            os = "Android";
        else if (ua.contains("iPhone") || ua.contains("iPad"))      os = "iOS";
        else if (ua.contains("Linux"))                              os = "Linux";
        else                                                         os = "Unknown OS";

        return browser + " on " + os;
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