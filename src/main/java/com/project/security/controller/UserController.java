package com.project.security.controller;

import com.project.security.dto.request.ChangePasswordRequest;
import com.project.security.dto.request.UpdateRoleRequest;
import com.project.security.dto.request.UpdateUserRequest;
import com.project.security.dto.response.UpdateUserResponse;
import com.project.security.dto.response.UserResponse;
import com.project.security.entity.User;
import com.project.security.repository.UserRepo;
import com.project.security.service.ImageService;
import com.project.security.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final UserRepo userRepo;
    private final ImageService imageService;

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id.toString() == authentication.principal.id.toString()")
    public ResponseEntity<UpdateUserResponse> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRequest request) {
        return ResponseEntity.ok(userService.updateUser(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id.toString() == authentication.principal.id.toString()")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok("User deleted successfully.");
    }

    @GetMapping("/")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUser());
    }

    @PutMapping("/me/password")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest request) {
        userService.changePassword(request);
        return ResponseEntity.ok("Password changed successfully.");
    }

    @PutMapping("/admin/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponse> updateUserRoles(
            @PathVariable Long id,
            @RequestBody UpdateRoleRequest request) {

        return ResponseEntity.ok(userService.updateUserRoles(id, request));
    }

    @PostMapping("/{id}/profile-image")
    @PreAuthorize("hasRole('ADMIN') or #id.toString() == authentication.principal.id.toString()")
    public ResponseEntity<?> uploadProfileImage(
            @PathVariable Long id,
            @RequestParam("image") MultipartFile file) throws IOException {

        String contentType = file.getContentType();
        if (contentType == null || !contentType.startsWith("image/")) {
            throw new IllegalArgumentException("Only image files are allowed");
        }

        User user = userRepo.findById(id).orElseThrow();

        String fileName = imageService.uploadProfileImage(id, file);
        user.setProfileImage(fileName);
        userRepo.save(user);

        return ResponseEntity.ok("Profile image uploaded");
    }
}
