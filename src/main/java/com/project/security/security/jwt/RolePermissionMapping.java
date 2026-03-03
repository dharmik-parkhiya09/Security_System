package com.project.security.security.jwt;

import com.project.security.enums.PermissionType;
import com.project.security.enums.RoleType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.project.security.enums.RoleType.*;


public class RolePermissionMapping {

    private static final Map<RoleType, Set<PermissionType>> map = Map.of(
            USER, Set.of(PermissionType.USER_READ),
            ADMIN, Set.of(PermissionType.USER_READ, PermissionType.USER_WRITE, PermissionType.USER_DELETE, PermissionType.USER_MANAGE)
    );

    public static Set<SimpleGrantedAuthority> getAuthoritiesForRole(RoleType role) {
        return map.getOrDefault(role, Collections.emptySet()).stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
    }
}

