package com.alibou.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * These permission string value, such as "admin:read", etc
 * are used in AdminController through @PreAuthorize
 */
@RequiredArgsConstructor
public enum Permission {
    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),
    MANAGER_READ("management:read"),
    MANAGER_UPDATE("management:update"),
    MANAGER_CREATE("management:create"),
    MANAGER_DELETE("management:delete");

    /**
     * Due to @RequiredArgsConstructor, we have a constructor as Permission(String permission): this.permission = permission
     * And ADMIN_READ("admin:read") will construct the private permission value = "admin:read"
     */
    @Getter
    private final String permission;
}
