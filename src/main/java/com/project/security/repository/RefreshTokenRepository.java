package com.project.security.repository;

import com.project.security.entity.RefreshToken;
import com.project.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByIdAndExpiresAtAfter(UUID id, Instant date);

    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(String refreshToken);

    void deleteByUser(User user);
}
