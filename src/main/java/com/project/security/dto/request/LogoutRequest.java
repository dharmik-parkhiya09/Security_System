package com.project.security.dto.request;



import lombok.Data;

@Data
public class LogoutRequest {
    private String refreshToken;
}
