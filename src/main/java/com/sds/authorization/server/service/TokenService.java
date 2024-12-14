package com.sds.authorization.server.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.sds.authorization.server.model.AuthorizationCodeChallenge;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.model.token.ClientLoginRequest;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.repo.CodeChallengeRepo;
import com.sds.authorization.server.repo.OauthClientRepository;
import com.sds.authorization.server.repo.UserRepository;
import com.sds.authorization.server.security.JwtTokenUtil;
import com.sds.authorization.server.utility.SdsObjMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.coyote.BadRequestException;
import org.checkerframework.checker.units.qual.A;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;

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
    private final CodeChallengeRepo codeChallengeRepo;
    private final OauthClientRepository oauthClientRepository;
    private final JwtTokenUtil jwtTokenUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public TokenService(UserRepository userRepository, CodeChallengeRepo codeChallengeRepo, JwtTokenUtil jwtTokenUtil, OauthClientRepository oauthClientRepository) {
        this.userRepository = userRepository;
        this.codeChallengeRepo = codeChallengeRepo;
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
            case MFA_TOKEN -> passwordToken();
            case CLIENT_CREDENTIALS -> clientCredentialsToken();
            case REFRESH_TOKEN -> refreshToken();
        };
    }

    private Token passwordToken() {

        String errorMsg = "UnAuthorised";
        try {
            if (tokenRequest.grantType().equalsIgnoreCase(GrantType.MFA_TOKEN.toString())) {

                Object object = jwtTokenUtil.verifyToken(tokenRequest.mfaToken());
                if (object instanceof EncryptedJWT encryptedJWT) {
                    JWTClaimsSet claimsSet = encryptedJWT.getJWTClaimsSet();
                    String userEmail = claimsSet.getStringClaim("email");
                    String clientId = claimsSet.getStringClaim("client_id");
                    String mfaCode = claimsSet.getStringClaim("code");
                    String tokenCode = claimsSet.getStringClaim("token_code");

                    if (mfaCode.equalsIgnoreCase(tokenRequest.mfaCode())) {
                        Optional<User> userOptional = userRepository.findByEmailOrUsername(userEmail, userEmail);
                        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(clientId);

                        if (userOptional.isPresent() && oauthClientDetails.isPresent()) {
                            return getToken(userOptional.get(), oauthClientDetails.get(), tokenCode);
                        }
                    }

                } else {
                    errorMsg = SdsObjMapper.jsonString(object);
                }
            } else {
                Optional<User> userOptional = userRepository.findByEmailOrUsername(tokenRequest.username(), tokenRequest.username());
                Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
                if (userOptional.isPresent() && oauthClientDetails.isPresent()) {
                    User user = userOptional.get();
                    OauthClientDetails oauthClient = oauthClientDetails.get();
                    log.info("GENERATING TOKEN FOR : {} ", user.getEmail());
                    if (verifyPassword(tokenRequest.password(), user.getPassword()) && verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {
                        try {
                            return getToken(user, oauthClient, null);
                        } catch (JOSEException e) {
                            log.error(e.getMessage(), e);
                        }
                    }
                }
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), errorMsg);
    }

    private Token getToken(User user, OauthClientDetails oauthClient, String tokenCode) throws JOSEException {
        String token = jwtTokenUtil.generateAccessToken(user, oauthClient, oauthClient.getClientId(), "test");
        String refresh = jwtTokenUtil.generateRefreshToken(user, oauthClient, oauthClient.getClientId(), "test");
        if (tokenCode != null) {

            List<AuthorizationCodeChallenge> codeChallenges = codeChallengeRepo.findAllByCodeAndClientId(tokenCode, oauthClient.getClientId());

            AuthorizationCodeChallenge codeChallenge = codeChallenges.getFirst();

            return new Token(
                    null,
                    null,
                    null,
                    null,
                    0,
                    null,
                    null,
                    false,
                    tokenCode,
                    codeChallenge.getCodeChallenge(),
                    codeChallenge.getRedirectUrl()
            );
        } else {
            return new Token(
                    null,
                    token,
                    refresh,
                    "Bearer",
                    oauthClient.getAccessTokenValidity(),
                    user.getRoles().stream().map(Role::getName).toList(),
                    "read,write",
                    user.isKycVerified(),
                    null,
                    null,
                    null
            );
        }
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
                    return mfaToken(oauthClient, user, null);
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
    }

    private Token mfaToken(OauthClientDetails oauthClient, User user, String tokenCode) {
        String token = jwtTokenUtil.generateMfaToken(SecurityContextHolder.getContext().getAuthentication(),
                UUID.randomUUID().toString(), oauthClient.getClientId(), generateOtp(), tokenCode);

        return new Token(
                token,
                null,
                null,
                "mfa_token",
                oauthClient.getAccessTokenValidity(),
                user.getRoles().stream().map(Role::getName).toList(),
                "read,write",
                user.isKycVerified(),
                tokenCode,
                null,
                null
        );
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
                            oauthClient.getClientId(),
                            "test");
                    return new Token(
                            null,
                            token,
                            null,
                            "Bearer",
                            oauthClient.getAccessTokenValidity(),
                            new ArrayList<>(),
                            "read,write",
                            true,
                            null,
                            null,
                            null
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
                String userID = jwt.getJWTClaimsSet().getStringClaim("email");
                String clientId = jwt.getJWTClaimsSet().getStringClaim("client_id");
                Optional<User> userOptional = userRepository.findByEmailOrUsername(userID, userID);
                Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(clientId);
                if (userOptional.isPresent() && oauthClientDetails.isPresent()) {
                    User user = userOptional.get();
                    OauthClientDetails oauthClient = oauthClientDetails.get();
                    log.info("GENERATING TOKEN FROM REFRESH TOKEN : {} ", user.getEmail());
                    String clientSecret = tokenRequest.clientSecret();
                    String clientID = tokenRequest.clientId();
                    if ((clientID.isBlank() & clientSecret.isBlank()) || verifyPassword(clientID, clientSecret)) {
                        try {
                            String token = jwtTokenUtil.generateAccessToken(user, oauthClient, oauthClient.getClientId(), "test");
                            String refresh = jwtTokenUtil.generateRefreshToken(user, oauthClient, oauthClient.getClientId(), "test");
                            return new Token(
                                    null,
                                    token,
                                    refresh,
                                    "Bearer",
                                    oauthClient.getAccessTokenValidity(),
                                    new ArrayList<>(),
                                    "read,write",
                                    user.isKycVerified(),
                                    null,
                                    null,
                                    null
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

    public Token processAuthorizationRequest(ClientLoginRequest loginRequest) throws BadRequestException {
        try {
            Optional<User> userOptional = userRepository.findByEmailOrUsername(loginRequest.username(), loginRequest.username());
            Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(loginRequest.clientId());

            if (oauthClientDetails.isPresent() && userOptional.isPresent() &&
                    verifyPassword(loginRequest.password(), userOptional.get().getPassword())) {

                //Confirm redirect URL
                User user = userOptional.get();
                String tokenCode = tokenCode();

                AuthorizationCodeChallenge codeChallenge = AuthorizationCodeChallenge.builder()
                        .codeChallengeId(UUID.nameUUIDFromBytes((loginRequest.codeChallenge() + loginRequest.clientId())
                                .getBytes(StandardCharsets.UTF_8)).toString())
                        .createdAt(Timestamp.valueOf(LocalDateTime.now()))
                        .updatedAt(Timestamp.valueOf(LocalDateTime.now()))
                        .codeChallenge(loginRequest.codeChallenge())
                        .codeChallengeMethod(loginRequest.codeChallengeMethod())
                        .redirectUrl(loginRequest.redirectUri())
                        .clientId(loginRequest.clientId())
                        .username(loginRequest.username())
                        .responseType(loginRequest.responseType())
                        .code(tokenCode)
                        .codeExpireAt(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC))
                        .isCodeUsed(false)
                        .build();

                codeChallengeRepo.save(codeChallenge);

                UsernamePasswordAuthenticationToken authenticatedToken = new UsernamePasswordAuthenticationToken(
                        user, user.getPassword(), Collections.singleton(new SimpleGrantedAuthority("pre-auth")));
                authenticatedToken.setDetails(user);
                SecurityContextHolder.getContext().setAuthentication(authenticatedToken);

                return mfaToken(oauthClientDetails.get(), user, tokenCode);

            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        throw new BadRequestException("Username or password invalid");

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
        return randomString(6);
    }

    private String tokenCode() {

        return randomString(50);
    }

    private String randomString(int length) {
        return RandomStringUtils.random(length, "123456789ACEFGHJKLMNPRTWXYZ123456789acefghjklmnprtwxyz");
    }

    enum GrantType {
        MFA_TOKEN("mfa_token"),
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
