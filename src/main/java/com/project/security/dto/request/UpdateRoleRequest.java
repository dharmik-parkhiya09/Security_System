package com.project.security.dto.request;

import com.project.security.enums.RoleType;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UpdateRoleRequest {
    private Set<RoleType> roles;
}
