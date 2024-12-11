package com.sds.authorization.server.security;

import com.sds.authorization.server.model.User;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * @author Joseph Kibe
 * Created on May 25, 2024.
 * Time 6:11 PM
 */

@Configuration
public class CustomAuthenticationManager implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
//
//    private Authentication successfulAuthentication(final Authentication authentication, final User user) {
//        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
//                user, user.getPassword(), user.getAuthorities());
//
//        token.setDetails(authentication.getDetails());
//
//        return token;
//    }
}
