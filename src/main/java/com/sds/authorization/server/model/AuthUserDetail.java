package com.sds.authorization.server.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


public class AuthUserDetail extends User implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        List.of(getRole()).forEach(role -> {
            grantedAuthorities.add(new SimpleGrantedAuthority(getRole().getName()));
            role.getPermissions().forEach(permission -> grantedAuthorities.add(new SimpleGrantedAuthority(permission.getPermissionName())));

        });
        return grantedAuthorities;
    }
}
