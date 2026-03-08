package com.project.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UpdateUserResponse {
    private UserResponse user;
    private String accessToken;
    private String refreshToken;
}
