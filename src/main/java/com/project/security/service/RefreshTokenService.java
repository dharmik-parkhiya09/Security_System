package com.project.security.service;

import com.project.security.entity.RefreshToken;
import com.project.security.entity.User;
import com.project.security.exception.TokenExpiredException;
import com.project.security.repository.RefreshTokenRepository;
import com.project.security.repository.UserRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepo  userRepo;

    private final long REFRESH_TOKEN_DURATION_TIME = 7 * 24 * 60 * 60;

    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepo.findById(userId).orElseThrow(()-> new UsernameNotFoundException("User not found"));

        refreshTokenRepository.deleteByUser(user);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiresAt(Instant.now().plusSeconds(REFRESH_TOKEN_DURATION_TIME));

        log.info("Refresh Token generated for {}",user.getUsername());

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(()-> new TokenExpiredException("Invalid Refresh Token"));

        if(refreshToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenExpiredException("Refresh Token Expired");
        }
        return refreshToken;
    }

    public void deleteByUser(User user) {
        refreshTokenRepository.deleteAll(user.getRefreshTokens());
    }

}
