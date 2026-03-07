package com.project.security.service;

import com.project.security.dto.request.RegisterRequest;
import com.project.security.dto.response.UserResponse;
import com.project.security.entity.User;
import com.project.security.exception.ResourceNotFoundException;
import com.project.security.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;

    public List<UserResponse> getAllUsers() {
        List<User> users = userRepo.findAll();
        return users.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }


    public UserResponse getUserById(Long id) {
        User user = userRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return mapToResponse(user);
    }


    public UserResponse updateUser(Long id, RegisterRequest request) {
        User user = userRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (request.getUsername() != null && !request.getUsername().trim().isEmpty()) {
            user.setUsername(request.getUsername().trim());
        }

        if (request.getPassword() != null && !request.getPassword().trim().isEmpty()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        user.setCreatedAt(ZonedDateTime.now(ZoneId.of("Asia/Kolkata")));
        User updatedUser = userRepo.save(user);
        return mapToResponse(updatedUser);
    }

    public void deleteUser(Long id) {
        User user = userRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
        userRepo.delete(user);
    }

    public UserResponse getCurrentUser(String username) {
        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        log.info("USER FOUND: {}", user.getUsername()); // ← add this
        log.info("USER ROLES: {}", user.getRoles());     // ← add this

        return mapToResponse(user);
    }

    private UserResponse mapToResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .roles(user.getRoles())
                .verified(user.isVerified())
                .build();
    }

}
