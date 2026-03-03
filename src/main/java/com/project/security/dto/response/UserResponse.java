package com.project.security.dto.response;

import com.project.security.enums.RoleType;
import lombok.Builder;
import lombok.Getter;

import java.util.Set;

@Builder
@Getter
public class UserResponse {

    private Long id;
    private String username;
    private Set<RoleType> roles;
    private boolean verified;
}