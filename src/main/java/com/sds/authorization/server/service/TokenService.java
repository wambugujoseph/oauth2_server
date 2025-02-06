package com.sds.authorization.server.service;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.sds.authorization.server.configuration.AppProps;
import com.sds.authorization.server.dto.InvalidateUserTokenRequest;
import com.sds.authorization.server.model.*;
import com.sds.authorization.server.model.message_broker.MessageBrokerSchema;
import com.sds.authorization.server.model.token.ClientLoginRequest;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.repo.CodeChallengeRepo;
import com.sds.authorization.server.repo.OauthClientRepository;
import com.sds.authorization.server.repo.UserTokenIdRepository;
import com.sds.authorization.server.security.JwtTokenUtil;
import com.sds.authorization.server.security.LoginCtrlService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import ua_parser.Client;
import ua_parser.Parser;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
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
    private final UserService userService;
    private final CodeChallengeRepo codeChallengeRepo;
    private final OauthClientRepository oauthClientRepository;
    private final JwtTokenUtil jwtTokenUtil;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final LoginCtrlService loginCtrlService;
    private final AppProps props;
    private final UserTokenIdRepository tokenIdRepository;

    public TokenService(UserService userService, CodeChallengeRepo codeChallengeRepo, JwtTokenUtil jwtTokenUtil, OauthClientRepository oauthClientRepository, LoginCtrlService loginCtrlService, AppProps props, UserTokenIdRepository tokenIdRepository) {
        this.userService = userService;
        this.codeChallengeRepo = codeChallengeRepo;
        this.oauthClientRepository = oauthClientRepository;
        this.jwtTokenUtil = jwtTokenUtil;
        this.loginCtrlService = loginCtrlService;
        this.props = props;
        this.tokenIdRepository = tokenIdRepository;
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
            case AUTHORIZATION_CODE -> authorizationCode();
        };
    }

    private Token authorizationCode() {
        String error = "";

        try {
            String condeVerifier = this.tokenRequest.codeVerifier();
            String code = this.tokenRequest.code();

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication.isAuthenticated()) {

                Object principal = authentication.getPrincipal();
                String clientId = principal.toString();

                if (principal instanceof OauthClientDetails oauthClientDetails) {
                    clientId = oauthClientDetails.getClientId();
                }

                List<AuthorizationCodeChallenge> codeChallenges = codeChallengeRepo.findAllByCodeAndClientId(code, clientId);
                AuthorizationCodeChallenge codeChallenge = !codeChallenges.isEmpty() ? codeChallenges.getFirst() : null;

                long currentTime = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

                if (codeChallenge != null &&
                        codeChallenge.getCodeExpireAt() > currentTime &&  //Expiration check
                        codeChallengeVerified(CodeChallengeMethod.valueOf(codeChallenge.getCodeChallengeMethod()),  //challenge verification
                                codeChallenge.getCodeChallenge(), condeVerifier) &&
                        !codeChallenge.isCodeUsed() &&
                        codeChallenge.isOtpVerified() &&
                        codeChallenge.getRedirectUrl().equalsIgnoreCase(this.tokenRequest.redirectUri())
                ) {
                    User user = userService.getActiveUserByEmail(codeChallenge.getUsername());
                    if (principal instanceof OauthClientDetails oauthClientDetails) {
                        codeChallenge.setCodeUsed(true);
                        codeChallengeRepo.save(codeChallenge);
                        return getToken(user, oauthClientDetails, null, null);
                    } else {
                        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(clientId);
                        return getToken(user, oauthClientDetails.orElse(null), null, null);
                    }
                } else {
                    error = "Token challenge invalid or expired";
                }
            } else {
                error = "Invalid client id or secret";
            }

            return getToken(null, null, null, TokenError.builder()
                    .error(UnsuccessfulResponse.unauthorized_client)
                    .errorDescription(error)
                    .errorUri("")
                    .build());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return getToken(null, null, null, TokenError.builder()
                    .error(UnsuccessfulResponse.server_error)
                    .errorDescription(e.getMessage())
                    .errorUri("")
                    .build());
        }

    }

    private boolean codeChallengeVerified(CodeChallengeMethod challengeMethod, String codeChallenge, String codeVerifier) {

        try {
            if (challengeMethod.equals(CodeChallengeMethod.PLAIN)) {
                return codeChallenge.equals(codeVerifier);
            } else {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedHash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
                HexFormat hexFormat = HexFormat.of();
                String result = hexFormat.formatHex(encodedHash);

                return result.equals(codeChallenge);
            }
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
        }
        return false;
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
                        User user = userService.getActiveUserByEmail(userEmail);
                        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(clientId);

                        if (user != null && oauthClientDetails.isPresent()) {
                            return getToken(user, oauthClientDetails.get(), tokenCode, null);
                        }
                    }
                } else {

                    if (object instanceof LinkedHashMap<?, ?> obj) {
                        errorMsg = obj.get("error_description").toString();
                    } else {
                        errorMsg = "Invalid Access token";
                    }
                }
            } else {
                User user = userService.getActiveUserByEmail(tokenRequest.username());
                Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
                if (user != null && oauthClientDetails.isPresent()) {
                    OauthClientDetails oauthClient = oauthClientDetails.get();
                    log.info("GENERATING TOKEN FOR : {} ", user.getEmail());
                    if (verifyPassword(tokenRequest.password(), user.getPassword()) && verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {
                        return getToken(user, oauthClient, null, null);
                    } else {
                        loginCtrlService.useOTPBruteForceAttackPrevention(user.getEmail());
                    }
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return new Token(null, null, null, null, 0,
                null, null, null,
                null, null, TokenError.builder()
                .error(UnsuccessfulResponse.unauthorized_client)
                .errorDescription(errorMsg)
                .errorUri("")
                .build());
    }

    private Token getToken(User user, OauthClientDetails oauthClient, String tokenCode, TokenError error) {

        try {
            if (error != null) {
                return new Token(null, null, null, null, 0,
                        null, null, null, null, null, error);
            }

            if (tokenCode != null) {

                List<AuthorizationCodeChallenge> codeChallenges = codeChallengeRepo.findAllByCodeAndClientId(tokenCode, oauthClient.getClientId());
                AuthorizationCodeChallenge codeChallenge = codeChallenges.getFirst();

                codeChallenge.setOtpVerified(true);
                codeChallenge.setUpdatedAt(Timestamp.valueOf(LocalDateTime.now()));
                codeChallengeRepo.save(codeChallenge);

                return new Token(
                        null, null, null, null,
                        0,
                        null,
                        null,
                        tokenCode,
                        codeChallenge.getCodeChallenge(),
                        codeChallenge.getRedirectUrl(),
                        null
                );
            } else {
                String tokenID = UUID.nameUUIDFromBytes((user.getEmail() + ":" + Date.from(Instant.now()).getTime()).getBytes(StandardCharsets.UTF_8)).toString();

                String token = jwtTokenUtil.generateAccessToken(user, oauthClient, oauthClient.getClientId(), props.keyId(), tokenID);
                String refresh = jwtTokenUtil.generateRefreshToken(user, oauthClient, oauthClient.getClientId(), props.keyId(), tokenID);

                //Save the generated token
                saveTheToken(user, oauthClient, tokenID);
                return new Token(
                        null,
                        token,
                        refresh,
                        "Bearer",
                        oauthClient.getAccessTokenValidity(),
                        List.of(user.getRole().getName()),
                        "read,write",
                        null, null, null, null
                );
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return new Token(null, null, null, null, 0,
                    null, null, null,
                    null, null, TokenError.builder()
                    .error(UnsuccessfulResponse.server_error)
                    .errorDescription("Internal service error Occurred")
                    .errorUri("")
                    .build());
        }
    }

    @Transactional
    private void saveTheToken(User user, OauthClientDetails oauthClient, String tokenId) {
        HttpServletRequest servletRequest = this.tokenRequest.servletRequest();
        Map<String, String> clientInfo = new HashMap<>();
        try {
            String remoteAddr = servletRequest.getRemoteAddr();
            String remoteHost = servletRequest.getRemoteHost();
            String contentType = servletRequest.getHeader("content-type");
            String userAgent = servletRequest.getHeader("user-agent");
            Parser uaParser = new Parser();
            Client client = uaParser.parse(userAgent);

            clientInfo.put("os_family", client.os.family);
            clientInfo.put("device_family", client.device.family);
            clientInfo.put("userAgent_family", client.userAgent.family);
            clientInfo.put("remote_address", remoteAddr);
            clientInfo.put("remote_host", remoteHost);
            clientInfo.put("remote_user", oauthClient.getApplicationName());
            clientInfo.put("content_type", contentType);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        UserTokenId userTokenId = UserTokenId.builder()
                .userEmail(user.getEmail())
                .loggedInDevice(clientInfo.toString())
                .loggedInDeviceCount(0)
                .loggedInApp(oauthClient.getApplicationName())
                .tokenId(tokenId)
                .createdAt(Timestamp.valueOf(LocalDateTime.now()))
                .expireAt(Timestamp.valueOf(LocalDateTime.now().plusSeconds(oauthClient.getRefreshTokenValidity())))
                .status("ACTIVE")
                .build();
        this.tokenIdRepository.updateUserTokenIdStatusByEmailAndLoggedInApp("LOGGED-OUT", user.getEmail(),
                oauthClient.getApplicationName());
        this.tokenIdRepository.save(userTokenId);
    }

    private Token mfaToken() {
        User user = userService.getActiveUserByEmail(tokenRequest.username());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.isAuthenticated() && authentication.getPrincipal() instanceof OauthClientDetails oauthClientDetails) {
            if (user != null) {
                log.info("GENERATING MFA TOKEN FOR : {} ", user.getEmail());
                if (!user.isApiAccess()) {
                    if (verifyPassword(tokenRequest.password(), user.getPassword())) {

                        UsernamePasswordAuthenticationToken authenticatedToken = new UsernamePasswordAuthenticationToken(
                                user, user.getPassword(), Collections.singleton(new SimpleGrantedAuthority("pre-auth")));
                        authenticatedToken.setDetails(user);
                        SecurityContextHolder.getContext().setAuthentication(authenticatedToken);
                        try {
                            Token token = mfaToken(oauthClientDetails, user, null, null);

                            return new Token(
                                    token.mfaToken(),
                                    token.accessToken(),
                                    token.refreshToken(),
                                    token.tokenType(),
                                    token.expireIn(),
                                    null,
                                    null,
                                    null,
                                    null,
                                    null,
                                    token.error());
                        } catch (Exception e) {
                            log.error(e.getMessage(), e);
                        }
                    } else {
                        loginCtrlService.userBruteForceAttackPrevention(user.getEmail());
                    }
                } else {
                    // FOR NONE MFA
                    if (tokenRequest.password().equals(user.getApiPassword())) {
                        return getToken(user, oauthClientDetails, null, null);
                    }
                }
            }
        } else {
            return new Token(null, null, null, null, 0,
                    null, null, null,
                    null, null, TokenError.builder()
                    .error(UnsuccessfulResponse.unauthorized_client)
                    .errorDescription("Unauthorized")
                    .errorUri("")
                    .build());
        }

        return mfaToken(null, null, null, TokenError.builder()
                .error(UnsuccessfulResponse.invalid_request)
                .errorDescription("user not found")
                .build());
    }

    private Token mfaToken(OauthClientDetails oauthClient, User user, String tokenCode, TokenError error) {
        if (error != null) {
            return new Token(null, null, null, null, 0,
                    null, null, null,
                    null, null, error);
        }

        String token = jwtTokenUtil.generateMfaToken(SecurityContextHolder.getContext().getAuthentication(),
                UUID.randomUUID().toString(), oauthClient.getClientId(), generateOtp(), tokenCode);

        return new Token(
                token,
                null,
                null,
                "mfa_token",
                oauthClient.getAccessTokenValidity(),
                List.of(user.getRole().getName()),
                "read,write",
                tokenCode, null, null, null
        );
    }

    private Token clientCredentialsToken() {
        Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(tokenRequest.clientId());
        if (oauthClientDetails.isPresent()) {
            OauthClientDetails oauthClient = oauthClientDetails.get();
            if (verifyPassword(tokenRequest.clientSecret(), oauthClient.getClientSecret())) {
                try {
                    String tokenID = UUID.nameUUIDFromBytes((oauthClient.getClientId() + ":" + Date.from(Instant.now()).getTime()).getBytes(StandardCharsets.UTF_8)).toString();
                    String token = jwtTokenUtil.generateAccessToken(
                            User.builder()
                                    .role(null)
                                    .build(),
                            oauthClient,
                            oauthClient.getClientId(),
                            props.keyId(),
                            tokenID
                    );
                    return new Token(
                            null,
                            token,
                            null,
                            "Bearer",
                            oauthClient.getAccessTokenValidity(),
                            new ArrayList<>(),
                            "read,write",
                            null, null, null, null
                    );
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        throw new ResponseStatusException(HttpStatusCode.valueOf(401), "UnAuthorised");
    }

    private Token refreshToken() {
        try {

            EncryptedJWT jwt = jwtTokenUtil.decodeToken(tokenRequest.refreshToken());

            if (jwt != null && jwt.getJWTClaimsSet().getStringClaim("typ").equals("refresh")) {
                String userID = jwt.getJWTClaimsSet().getStringClaim("email");
                String clientId = jwt.getJWTClaimsSet().getStringClaim("client_id");
                User user = userService.getActiveUserByEmail(userID);
                Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(clientId);
                if (user != null && oauthClientDetails.isPresent()) {

                    OauthClientDetails oauthClient = oauthClientDetails.get();
                    log.info("GENERATING TOKEN FROM REFRESH TOKEN : {} ", user.getEmail());
                    String clientSecret = tokenRequest.clientSecret();
                    String clientID = tokenRequest.clientId();
                    if ((clientID.isBlank() & clientSecret.isBlank()) || verifyPassword(clientID, clientSecret)) {
                        try {
                            return getToken(user, oauthClient, null, null);
                        } catch (Exception e) {
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

    public Token processAuthorizationRequest(ClientLoginRequest loginRequest) {
        try {
            User user = userService.getActiveUserByEmail(loginRequest.username());
            Optional<OauthClientDetails> oauthClientDetails = oauthClientRepository.findById(loginRequest.clientId());

            if (oauthClientDetails.isPresent() && user != null &&
                    verifyPassword(loginRequest.password(), user.getPassword())) {
                //Confirm redirect URL

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
                        .codeExpireAt(LocalDateTime.now().plusHours(6).toEpochSecond(ZoneOffset.UTC))
                        .isCodeUsed(false)
                        .isOtpVerified(false)
                        .build();

                //Prevent replay of the login challenge
                if (!codeChallengeRepo.findAllByCodeChallengeAndClientId(loginRequest.codeChallenge(), loginRequest.clientId()).isEmpty()) {
                    return mfaToken(null, null, null, TokenError.builder()
                            .error(UnsuccessfulResponse.invalid_request)
                            .errorDescription("Request blocked, Expired code challenge")
                            .build());
                }

                //Validate URL
                String urlValidationMsg = UriValidator.isRedirectUriValid(loginRequest.redirectUri());

                if (urlValidationMsg == null || props.env().equalsIgnoreCase("TEST")) {
                    urlValidationMsg = UriValidator.compareRedirectUrlTOClientRedirect(loginRequest.redirectUri(),
                            oauthClientDetails.get().getWebServerRedirectUri());
                }

                if (urlValidationMsg == null || props.env().equalsIgnoreCase("TEST")) {
                    codeChallengeRepo.save(codeChallenge);

                    UsernamePasswordAuthenticationToken authenticatedToken = new UsernamePasswordAuthenticationToken(
                            user, user.getPassword(), Collections.singleton(new SimpleGrantedAuthority("pre-auth")));
                    authenticatedToken.setDetails(user);
                    SecurityContextHolder.getContext().setAuthentication(authenticatedToken);

                    Token token = mfaToken(oauthClientDetails.get(), user, tokenCode, null);
                    return new Token(
                            token.mfaToken(),
                            token.accessToken(),
                            token.refreshToken(),
                            token.tokenType(),
                            token.expireIn(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            token.error());
                } else {
                    return mfaToken(null, null, null, TokenError.builder()
                            .error(UnsuccessfulResponse.invalid_request)
                            .errorDescription(urlValidationMsg)
                            .build());
                }

            } else {
                return mfaToken(null, null, null, TokenError.builder()
                        .error(UnsuccessfulResponse.unauthorized_client)
                        .errorDescription("Invalid username or password")
                        .build());
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return mfaToken(null, null, null, TokenError.builder()
                .error(UnsuccessfulResponse.server_error)
                .errorDescription("Failed to Authorize user")
                .build());
    }

    public CustomResponse invalidateUserAccessToken(InvalidateUserTokenRequest invalidateUserTokenRequest) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication.isAuthenticated() && invalidateUserTokenRequest != null) {

            if (invalidateUserTokenRequest.isFullInvalidation()) {
                tokenIdRepository.updateUserTokenIdStatus("LOGGED-OUT", invalidateUserTokenRequest.getEmail());
            } else {
                tokenIdRepository.updateUserTokenIdStatus("LOGGED-OUT", invalidateUserTokenRequest.getTokenId(),
                        invalidateUserTokenRequest.getEmail());
            }
            return CustomResponse.builder()
                    .responseCode("200")
                    .responseDesc("User logged out successfully")
                    .build();
        } else {
            return CustomResponse.builder()
                    .error(UnsuccessfulResponse.unauthorized_client)
                    .errorDescription("Unauthorized client invalidation request")
                    .build();
        }
    }

    public CustomResponse isUserAccessTokenValid(String tokenId){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication.isAuthenticated() && tokenId != null){
            if (tokenIdRepository.findByTokenIdAndStatus(tokenId, "ACTIVE").isPresent()){
                return CustomResponse.builder()
                        .responseCode("200")
                        .responseDesc("Token is Valid")
                        .build();
            }else {
                return CustomResponse.builder()
                        .responseCode("400")
                        .responseDesc("Toke is InValid")
                        .build();
            }
        }else {
            return CustomResponse.builder()
                    .error(UnsuccessfulResponse.unauthorized_client)
                    .errorDescription("Unauthorized client invalidation request")
                    .build();
        }

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
        return randomString(6).toUpperCase();
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
        REFRESH_TOKEN("refresh_token"),
        AUTHORIZATION_CODE("authorization_code");

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
