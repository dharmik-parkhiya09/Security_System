package com.project.security.dto.request;

import lombok.*;

@Getter
@Setter
public class ResetPasswordRequest {

    private String token;
    private String newPassword;
}
