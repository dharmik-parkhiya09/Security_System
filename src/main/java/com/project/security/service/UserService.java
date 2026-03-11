package com.project.security.service;

import com.project.security.dto.request.ChangePasswordRequest;
import com.project.security.dto.request.RegisterRequest;
import com.project.security.dto.request.UpdateRoleRequest;
import com.project.security.dto.request.UpdateUserRequest;
import com.project.security.dto.response.UpdateUserResponse;
import com.project.security.dto.response.UserResponse;
import com.project.security.entity.User;
import com.project.security.exception.ResourceNotFoundException;
import com.project.security.repository.PasswordResetTokenRepo;
import com.project.security.repository.UserRepo;
import com.project.security.security.jwt.JwtTokenProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepo passwordResetTokenRepo;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    public List<UserResponse> getAllUsers() {
        List<User> users = userRepo.findAll();
        return users.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public UserResponse getUserById(Long id) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return mapToResponse(user);
    }

    public UpdateUserResponse updateUser(Long id, UpdateUserRequest request) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (request.getUsername() != null && !request.getUsername().trim().isEmpty()) {
            user.setUsername(request.getUsername().trim());
        }

        if (request.getEmail() != null && !request.getEmail().trim().isEmpty()) {
            user.setEmail(request.getEmail().trim());
        }

        User updatedUser = userRepo.save(user);

        String newAccessToken = jwtTokenProvider.generateToken(updatedUser);
        String newRefreshToken = refreshTokenService.createRefreshToken(updatedUser.getId()).getToken();

        return new UpdateUserResponse(mapToResponse(updatedUser), newAccessToken, newRefreshToken);
    }

    public void deleteUser(Long id) {

        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        passwordResetTokenRepo.deleteByUser(user);

        userRepo.delete(user);
    }

    public UserResponse getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return mapToResponse(user);
    }

    public void changePassword(ChangePasswordRequest request) {

        String username = SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getName();

        User user = userRepo.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Old password doesn't match");
        }

        if (request.getNewPassword().length() < 6) {
            throw new RuntimeException("Password must be at least 6 characters");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepo.save(user);
    }

    public UserResponse updateUserRoles(Long id, UpdateRoleRequest request) {

        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (request.getRoles() == null || request.getRoles().isEmpty()) {
            throw new RuntimeException("Roles cannot be empty");
        }

        user.setRoles(request.getRoles());
        User updatedUser = userRepo.save(user);
        return mapToResponse(updatedUser);
    }

    private UserResponse mapToResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .verified(user.isVerified())
                .profileImage(user.getProfileImage())
                .build();
    }
}