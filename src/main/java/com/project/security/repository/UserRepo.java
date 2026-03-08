package com.project.security.repository;

import com.project.security.entity.User;
import com.project.security.enums.AuthProviderType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByProviderIdAndProvider(String providerId, AuthProviderType providerType);

    Optional<User> findByVerificationToken(String token);

    Optional<User> findByEmail(String email);
}
