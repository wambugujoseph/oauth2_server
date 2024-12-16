package com.sds.authorization.server.security;

import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.repo.OauthClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on May 25, 2024.
 * Time 6:11 PM
 */

@Slf4j
@Configuration
public class CustomAuthenticationManager implements AuthenticationProvider {

    private final OauthClientRepository clientRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public CustomAuthenticationManager(OauthClientRepository clientRepository) {
        this.clientRepository = clientRepository;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder(
                BCryptPasswordEncoder.BCryptVersion.$2A, 10, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String clientId = authentication.getName();
        String clientCredentials = authentication.getCredentials().toString();
        Optional<OauthClientDetails> clientDetailsOptional = clientRepository.findById(clientId);

        if (clientDetailsOptional.isPresent() && verifyPassword(clientCredentials, clientDetailsOptional.get().getClientSecret()) ){
            log.info("Client Authenticated");
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(clientDetailsOptional.get(), clientCredentials, Collections.singleton(new SimpleGrantedAuthority("client")));
            token.setDetails(authentication.getDetails());
            return token;

        }else {
            authentication.setAuthenticated(false);
        }
        return authentication;
    }

    public boolean verifyPassword(CharSequence rawPassword, String encodedPassword) {
        try {
            return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
