package com.sds.authorization.server.security;

import com.nimbusds.jose.JOSEException;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 11:41 AM
 */

@Service
@Slf4j
public class TokenService {


    private TokenRequest tokenRequest;
    private final UserRepository userRepository;
    private final JwtTokenUtil jwtTokenUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public TokenService(UserRepository userRepository, JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.jwtTokenUtil = jwtTokenUtil;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder(
                BCryptPasswordEncoder.BCryptVersion.$2A, 10, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8)));

    }

    public Token tokenGeneratorHandler(TokenRequest tokenRequest) {

        this.tokenRequest = tokenRequest;
        log.info("Handler");
        return switch (GrantType.valueOf(tokenRequest.grantType().toUpperCase())) {
            case PASSWORD -> passwordToken();
            case CLIENT_CREDENTIALS -> clientCredentialsToken();
        };
    }

    private Token passwordToken() {
        Optional<User> userOptional = userRepository.findByEmailOrUsername(tokenRequest.username(), tokenRequest.username());
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            log.info("GENERATING TOKEN FOR : {} ", user.getEmail());
            if (verifyPassword(tokenRequest.password(), user.getPassword())) {
                try {
                    String token = jwtTokenUtil.generateAccessToken(user, "test");
                    return new Token(
                         token,
                         "",
                         "Bearer",
                         3600,
                         "read,write"
                    );
                } catch (JOSEException e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
    }

    private Token clientCredentialsToken() {
        log.info("Credentials");
        return null;
    }

    public Object getTokenInfo(String token){
        return jwtTokenUtil.verifyToken(token);
    }

    public boolean verifyPassword(CharSequence rawPassword, String encodedPassword) {
        try {
            return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
        } catch (Exception e) {
            return false;
        }
    }


    enum GrantType {
        PASSWORD("password"),
        CLIENT_CREDENTIALS("client_credentials");

        private final String value;

        GrantType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }
    }
}
