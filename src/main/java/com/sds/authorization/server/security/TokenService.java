package com.sds.authorization.server.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.repo.OauthClientRepository;
import com.sds.authorization.server.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

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
    private final OauthClientRepository oauthClientRepository;
    private final JwtTokenUtil jwtTokenUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public TokenService(UserRepository userRepository, JwtTokenUtil jwtTokenUtil, OauthClientRepository oauthClientRepository) {
        this.userRepository = userRepository;
        this.oauthClientRepository = oauthClientRepository;
        this.jwtTokenUtil = jwtTokenUtil;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder(
                BCryptPasswordEncoder.BCryptVersion.$2A, 10, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8)));

    }

    public Token tokenGeneratorHandler(TokenRequest tokenRequest) {

        this.tokenRequest = tokenRequest;
        log.info("Handler");
        return switch (GrantType.valueOf(tokenRequest.grantType().toUpperCase())) {
            case PASSWORD -> mfaToken();
            case MFA_OTP -> passwordToken();
            case CLIENT_CREDENTIALS -> clientCredentialsToken();
            case REFRESH_TOKEN -> refreshToken();
        };
    }

    private Token passwordToken() {
        Optional<User> userOptional = userRepository.findByEmailOrUsername(tokenRequest.username(), tokenRequest.username());
        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
        if (userOptional.isPresent() && oauthClientDetails.isPresent()) {
            User user = userOptional.get();
            OauthClientDetails oauthClient = oauthClientDetails.get();
            log.info("GENERATING TOKEN FOR : {} ", user.getEmail());
            if (verifyPassword(tokenRequest.password(), user.getPassword()) && verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {
                try {
                    String token = jwtTokenUtil.generateAccessToken(user, oauthClient, "test");
                    String refresh = jwtTokenUtil.generateRefreshToken(user, oauthClient, "test");
                    return new Token(
                            null,
                            token,
                            refresh,
                            "Bearer",
                            oauthClient.getAccessTokenValidity(),
                            user.getRoles().stream().map(Role::getName).toList(),
                            "read,write",
                            user.isKycVerified()
                    );
                } catch (JOSEException e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
    }

    private Token mfaToken() {
        Optional<User> userOptional = userRepository.findByEmailOrUsername(tokenRequest.username(), tokenRequest.username());
        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
        if (userOptional.isPresent() && oauthClientDetails.isPresent()) {
            User user = userOptional.get();
            OauthClientDetails oauthClient = oauthClientDetails.get();
            log.info("GENERATING MFA TOKEN FOR : {} ", user.getEmail());
            if (verifyPassword(tokenRequest.password(), user.getPassword()) && verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {

                UsernamePasswordAuthenticationToken authenticatedToken = new UsernamePasswordAuthenticationToken(
                        user, user.getPassword(), Collections.singleton(new SimpleGrantedAuthority("pre-auth")));
                authenticatedToken.setDetails(user);
                SecurityContextHolder.getContext().setAuthentication(authenticatedToken);
                try {
                    String token = jwtTokenUtil.generateMfaToken(SecurityContextHolder.getContext().getAuthentication(),
                            UUID.randomUUID().toString(), generateOtp());
                    return new Token(
                            token,
                            null,
                            null,
                            "Bearer",
                            oauthClient.getAccessTokenValidity(),
                            user.getRoles().stream().map(Role::getName).toList(),
                            "read,write",
                            user.isKycVerified()
                    );
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
    }

    private Token clientCredentialsToken() {
        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
        if (oauthClientDetails.isPresent()) {
            OauthClientDetails oauthClient = oauthClientDetails.get();
            if (verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {
                try {
                    String token = jwtTokenUtil.generateAccessToken(
                            User.builder()
                                    .roles(new ArrayList<>())
                                    .build(),
                            oauthClient,
                            "test");
                    return new Token(
                            null,
                            token,
                            null,
                            "Bearer",
                            oauthClient.getAccessTokenValidity(),
                            new ArrayList<>(),
                            "read,write",
                            true
                    );
                } catch (JOSEException e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
    }

    private Token refreshToken() {
        try {
            EncryptedJWT jwt = jwtTokenUtil.decodeToken(tokenRequest.refreshToken());

            if (jwt.getJWTClaimsSet().getStringClaim("typ").equals("refresh")) {
                String userID = jwt.getJWTClaimsSet().getStringClaim("uid");
                Optional<User> userOptional = userRepository.findByEmailOrUsername(userID, userID);
                Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
                if (userOptional.isPresent() && oauthClientDetails.isPresent()) {
                    User user = userOptional.get();
                    OauthClientDetails oauthClient = oauthClientDetails.get();
                    log.info("GENERATING TOKEN FROM REFRESH TOKEN : {} ", user.getEmail());
                    if (verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {
                        try {
                            String token = jwtTokenUtil.generateAccessToken(user, oauthClient, "test");
                            String refresh = jwtTokenUtil.generateRefreshToken(user, oauthClient, "test");
                            return new Token(
                                    null,
                                    token,
                                    refresh,
                                    "Bearer",
                                    oauthClient.getAccessTokenValidity(),
                                    new ArrayList<>(),
                                    "read,write",
                                    user.isKycVerified()
                            );
                        } catch (JOSEException e) {
                            log.error(e.getMessage(), e);
                        }
                    }
                }
                throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public Object getTokenInfo(String token) {
        return jwtTokenUtil.verifyToken(token);
    }

    public boolean verifyPassword(CharSequence rawPassword, String encodedPassword) {
        try {
            return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
        } catch (Exception e) {
            return false;
        }
    }

    public String generateOtp() {
        return RandomStringUtils.random(6, "123456789ACEFGHJKLMNPRTWXYZ123456789");
    }

    enum GrantType {
        MFA_OTP("mfa_otp"),
        PASSWORD("password"),
        CLIENT_CREDENTIALS("client_credentials"),
        REFRESH_TOKEN("refresh_token");

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
