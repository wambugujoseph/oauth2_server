package com.sds.authorization.server.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.sds.authorization.server.model.AuthUserDetail;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.service.NotificationService;
import com.sds.authorization.server.utility.SdsObjMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * @author Joseph Kibe
 * Created on May 12, 2023.
 * Time 12:37 PM
 */

@Slf4j
@Component
public class JwtTokenUtil {

    private final KeyStore keyStore;
    private final NotificationService notificationService;

    public JwtTokenUtil(KeyStore keyStore, NotificationService notificationService) {
        this.keyStore = keyStore;
        this.notificationService = notificationService;
    }

    private static EncryptedJWT getEncryptedJWT(String keyId, JWTClaimsSet jwtClaims) {
        JWEHeader header = new JWEHeader(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128GCM,
                JOSEObjectType.JWT,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                keyId,
                null,
                null,
                null,
                null,
                null,
                0,
                null,
                null,
                null,
                null,
                null
        );

        // Create the encrypted JWT object
        return new EncryptedJWT(header, jwtClaims);
    }

    public String generateAccessToken(User user, OauthClientDetails oauthClientDetails, String clientID,String keyId) throws JOSEException {
        LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
        Date now = Date.from(current.toInstant(ZoneOffset.UTC));
        Date exp = Date.from(current.plusSeconds(oauthClientDetails.getAccessTokenValidity()).toInstant(ZoneOffset.UTC));

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer(UUID.randomUUID().toString())
                .subject("SDS-APP")
                .audience(UUID.randomUUID().toString())
                .expirationTime(exp) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .claim("roles", user.isKycVerified() ? user.getRoles().stream().map(Role::getName).collect(Collectors.toList()) : "NOT-VERIFIED")
                .claim("typ", "access_token")
                .claim("name", user.getUsername())
                .claim("email", user.getEmail())
                .claim("userid", user.getUserId())
                .claim("verified", user.isKycVerified())
                .claim("client_id", clientID)
                .jwtID(UUID.randomUUID().toString())
                .build();

        EncryptedJWT jwt = getEncryptedJWT("test", jwtClaims);
        jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));
        return jwt.serialize();
    }

    public String generateRefreshToken(User user, OauthClientDetails oauthClientDetails, String clientId, String keyId) throws JOSEException {
        LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
        Date now = Date.from(current.toInstant(ZoneOffset.UTC));
        Date exp = Date.from(current.plusSeconds(oauthClientDetails.getRefreshTokenValidity()).toInstant(ZoneOffset.UTC));

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer(UUID.randomUUID().toString())
                .subject("SDS-APP")
                .audience(UUID.randomUUID().toString())
                .expirationTime(exp) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .claim("typ", "refresh")
                .claim("uid", user.getUsername())
                .claim("email", user.getEmail())
                .claim("client_id", clientId)
                .jwtID(UUID.randomUUID().toString())
                .build();

        EncryptedJWT jwt = getEncryptedJWT("test", jwtClaims);
        jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));
        return jwt.serialize();
    }


    public String generateMfaToken(Authentication authentication, String jwtId, String clientId, String code, String tokenCode) {

        try {

            if (authentication.isAuthenticated()) {
                String userEmail = "";
                String username;
                String userCompId = "";
                String id = "";

                if (authentication.getPrincipal() instanceof User authUserDetail) {
                    userEmail = authUserDetail.getEmail();
                    username = authUserDetail.getUsername();
                    id = authUserDetail.getUserId();
                } else {
                    username = authentication.getPrincipal().toString();
                }

                String msg = "Your BridgeUI OTP code is: <b>" + code + "</b>. It will be active for the next 02:00 minutes.";
                notificationService.sendEmailNotification(Date.from(Instant.now()).getTime() + "", msg,
                        "BRIDGE OTP",
                        List.of(userEmail).toArray(new String[0])
                );

                LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
                Date now = Date.from(current.toInstant(ZoneOffset.UTC));
                Date expire = Date.from(current.plusSeconds(120).toInstant(ZoneOffset.UTC));
                String keyId = "test";

                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("pre-auth"));

                JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                        .issuer("SLA")
                        .subject(username)
                        .audience("client")
                        .expirationTime(expire) // expires in 10 minutes
                        .notBeforeTime(now)
                        .issueTime(now)
                        .claim("id", id)
                        .claim("usp", authorities)//User Permission
                        .claim("usercompid", userCompId)
                        .claim("code", code)
                        .claim("token_code", tokenCode)
                        .claim("email", userEmail)
                        .claim("client_id", clientId)
                        .jwtID(jwtId)
                        .build();

                EncryptedJWT jwt = getEncryptedJWT(keyId, jwtClaims);
                jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));

                return jwt.serialize();
            }
            authentication.setAuthenticated(false);
            throw new ResponseStatusException(HttpStatusCode.valueOf(UNAUTHORIZED.value()));
        } catch (Exception e) {
            log.error("Error Creating the Token: {}", e.getMessage());
            throw new ResponseStatusException(UNAUTHORIZED, UNAUTHORIZED.toString());
        }
    }


    public Object verifyToken(String token) {
        try {
            EncryptedJWT jwt = EncryptedJWT.parse(token);
            String keyId = jwt.getHeader().getKeyID();
            jwt.decrypt(new RSADecrypter(keyStore.getPrivateKey(keyId)));
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            Date exp = claimsSet.getExpirationTime();
            LocalDateTime lExp = LocalDateTime.ofInstant(exp.toInstant(), ZoneOffset.UTC);
            LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
            if (lExp.isAfter(now)) {
                return jwt;
            } else {
                return new LinkedHashMap<String, String>() {{
                    put("status", "invalid");
                    put("error", "invalid_token");
                    put("error_description", "Token has Expired");
                }};
            }
        } catch (Exception e) {
            log.error("Invalid token: {}", e.getMessage());
        }
        return new LinkedHashMap<String, String>() {{
            put("status", "invalid");
            put("error", "invalid_token");
            put("error_description", "invalid token");
        }};
    }

    public EncryptedJWT decodeToken(String token) {
        try {
            //RSA/ECB/OAEPWithSHA-256AndMGF1Padding
            EncryptedJWT jwt = EncryptedJWT.parse(token);
            jwt.decrypt(new RSADecrypter(keyStore.getPrivateKey(jwt.getHeader().getKeyID())));
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            Date exp = claimsSet.getExpirationTime();
            LocalDateTime lExp = LocalDateTime.ofInstant(exp.toInstant(), ZoneOffset.UTC);
            LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);

            if (lExp.isAfter(now)) {
                return jwt;
            } else {
                log.warn("Authorization failed");
            }
        } catch (Exception e) {
            log.warn("Unauthorised: " + e.getMessage());
            SecurityContextHolder.clearContext();
            throw new ResponseStatusException(UNAUTHORIZED, "UnAuthorised");
        }
        return null;
    }

}