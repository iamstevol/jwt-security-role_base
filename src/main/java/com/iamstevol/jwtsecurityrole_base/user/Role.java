package com.iamstevol.jwtsecurityrole_base.user;

import lombok.RequiredArgsConstructor;

import java.util.Collections;
import java.util.Set;

import static com.iamstevol.jwtsecurityrole_base.user.Permission.*;

@RequiredArgsConstructor
public enum Role {

    USER(Collections.emptySet()),

    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_CREATE,
                    ADMIN_DELETE,
                    MANAGER_READ,
                    MANAGER_CREATE,
                    MANAGER_DELETE,
                    MANAGER_UPDATE
            )
    ),

    MANAGER(
            Set.of(
                    MANAGER_READ,
                    MANAGER_CREATE,
                    MANAGER_DELETE,
                    MANAGER_UPDATE
            )
    );

    private final Set<Permission> permissions;

    public List<Simple>
}
