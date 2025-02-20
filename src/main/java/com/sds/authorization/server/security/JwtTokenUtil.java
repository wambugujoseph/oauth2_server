package com.sds.authorization.server.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.sds.authorization.server.configuration.AppProps;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.Permission;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.service.NotificationService;
import lombok.extern.slf4j.Slf4j;
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

import static com.sds.authorization.server.service.NotificationServiceImpl.EmailTemplate;
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
    private final AppProps props;

    public JwtTokenUtil(KeyStore keyStore, NotificationService notificationService, AppProps props) {
        this.keyStore = keyStore;
        this.notificationService = notificationService;
        this.props = props;
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

    public String generateAccessToken(User user, OauthClientDetails oauthClientDetails, String clientID, String keyId, String tokenId) throws JOSEException {
        LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
        Date now = Date.from(current.toInstant(ZoneOffset.UTC));
        Date exp = Date.from(current.plusSeconds(oauthClientDetails.getAccessTokenValidity()).toInstant(ZoneOffset.UTC));

        List<Permission> permissions = user.getRole().getPermissions();

        List<GrantedAuthority> authorities = new ArrayList<>();
        permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getId() + "")));

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer(UUID.randomUUID().toString())
                .subject("APIUSER")
                .audience(UUID.randomUUID().toString())
                .expirationTime(exp) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .claim("roles", user.getRole().getName())
                .claim("roleid", user.getRole().getId() + "")
                .claim("usp", authorities)
                .claim("typ", "access_token")
                .claim("name", user.getName())
                .claim("email", user.getEmail())
                .claim("userid", user.getUserId())
                .claim("id", user.getId() + "")
                .claim("usercompid", user.getCompanyId())
                .claim("usercompname", user.getCompanyName())
                .claim("client_id", clientID)
                .claim("resetpass", user.isResetPassword())
                .claim("partner", user.getPartnerName())
                .jwtID(tokenId)
                .build();

        EncryptedJWT jwt = getEncryptedJWT(props.keyId(), jwtClaims);
        jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));
        return jwt.serialize();
    }

    public String generateRefreshToken(User user, OauthClientDetails oauthClientDetails, String clientId, String keyId, String tokenId) throws JOSEException {
        LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
        Date now = Date.from(current.toInstant(ZoneOffset.UTC));
        Date exp = Date.from(current.plusSeconds(oauthClientDetails.getRefreshTokenValidity()).toInstant(ZoneOffset.UTC));

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer(UUID.randomUUID().toString())
                .subject("APIUSER")
                .audience(UUID.randomUUID().toString())
                .expirationTime(exp) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .claim("typ", "refresh")
                .claim("uid", user.getUsername())
                .claim("email", user.getEmail())
                .claim("name", user.getName())
                .claim("id", user.getId() + "")
                .claim("usercompid", user.getCompanyId())
                .claim("usercompname", user.getCompanyName())
                .claim("client_id", clientId)
                .claim("resetpass", user.isResetPassword())
                .claim("partner", user.getPartnerName())
                .jwtID(tokenId)
                .build();

        EncryptedJWT jwt = getEncryptedJWT(keyId, jwtClaims);
        jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));
        return jwt.serialize();
    }

    public String generateMfaToken(Authentication authentication, String jwtId, String clientId, String code, String tokenCode) {

        try {
            if (authentication.isAuthenticated()) {
                String userEmail = "";
                String username;
                String userCompId = "";
                String name = "";
                String id = "";

                if (authentication.getPrincipal() instanceof User authUserDetail) {
                    userEmail = authUserDetail.getEmail();
                    username = authUserDetail.getUsername();
                    userCompId = authUserDetail.getCompanyId();
                    name = authUserDetail.getName();
                    id = authUserDetail.getId() + "";
                } else {
                    username = authentication.getPrincipal().toString();
                }

                String msg = "Your login OTP code is: <b>" + code + "</b>. It will be active for the next 02:00 minutes.";
                String body = String.format(EmailTemplate, "", msg);
                notificationService.sendEmailNotification(Date.from(Instant.now()).getTime() + "", body,
                        "ONE TIME PASSWORD",
                        List.of(userEmail).toArray(new String[0]),
                        userCompId
                );

                LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
                Date now = Date.from(current.toInstant(ZoneOffset.UTC));
                Date expire = Date.from(current.plusSeconds(120).toInstant(ZoneOffset.UTC));

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
                        .claim("name", name)
                        .claim("code", code)
                        .claim("token_code", tokenCode)
                        .claim("email", userEmail)
                        .claim("client_id", clientId)
                        .claim("resetpass", false)
                        .claim("partner", "")
                        .jwtID(jwtId)
                        .build();

                EncryptedJWT jwt = getEncryptedJWT(props.keyId(), jwtClaims);
                jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(props.keyId())));

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

            log.error("Invalid token: {}", e.getMessage(), e);
        }
        return new LinkedHashMap<String, String>() {{
            put("status", "invalid");
            put("error", "invalid_token");
            put("error_description", "invalid token");
        }};
    }

    /**
     * Jwt Token decoder
     *
     * @param token String to be decoded
     * @return jwt if decoded successfully else NULL
     */
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