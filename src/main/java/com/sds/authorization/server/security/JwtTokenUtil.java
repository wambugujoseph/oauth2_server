package com.sds.authorization.server.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Joseph Kibe
 * Created on May 12, 2023.
 * Time 12:37 PM
 */

@Slf4j
@Component
public class JwtTokenUtil {

    private KeyStore keyStore;

    public JwtTokenUtil(KeyStore keyStore) {
        this.keyStore = keyStore;
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

    public String generateAccessToken(User user, OauthClientDetails oauthClientDetails, String keyId) throws JOSEException {
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
                .claim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .claim("typ","access")
                .jwtID(UUID.randomUUID().toString())
                .build();

        EncryptedJWT jwt = getEncryptedJWT("test", jwtClaims);
        jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));
        return jwt.serialize();
    }

    public String generateRefreshToken(User user, OauthClientDetails oauthClientDetails, String keyId) throws JOSEException {
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
                .claim("typ","refresh")
                .claim("uid", user.getUsername())
                .jwtID(UUID.randomUUID().toString())
                .build();

        EncryptedJWT jwt = getEncryptedJWT("test", jwtClaims);
        jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));
        return jwt.serialize();
    }



    /*
    public String generateMfaToken(Authentication authentication, String jwtId, String code) {

        try {
            // Context holder has the authorized uses
            // If a user is authenticated
            if (authentication.isAuthenticated()) {
                String userEmail = "";
                String partnerUsername;
                String userCompId = "";
                String id = "";

                if (authentication.getPrincipal() instanceof CustomUserDetails customUserDetails) {
                    userEmail = customUserDetails.getEmail();
                    partnerUsername = customUserDetails.getUsername();
                    id = customUserDetails.getUserId();
                    userCompId = customUserDetails.getUserCompanyId();
                } else {
                    partnerUsername = authentication.getPrincipal().toString();
                }

                Partner partner = Optional.ofNullable(partnerService.getPartnerByPartnerUsername(partnerUsername)).orElse(new Partner());
                LocalDateTime current = LocalDateTime.now(ZoneOffset.UTC);
                Date now = Date.from(current.toInstant(ZoneOffset.UTC));
                Date expire = Date.from(current.plusSeconds(120).toInstant(ZoneOffset.UTC));
                String keyId = Optional.ofNullable(partner.getKeyId()).orElse("none");

                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("pre-auth"));

                JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                        .issuer("SLA")
                        .subject(partner.getPartnerId())
                        .audience("partner")
                        .expirationTime(expire) // expires in 10 minutes
                        .notBeforeTime(now)
                        .issueTime(now)
                        .claim("id", id)
                        .claim("usp", authorities)//User Permission
                        .claim("usercompid", userCompId)
                        .claim("code", code)
                        .claim("email", userEmail)
                        .jwtID(jwtId)
                        .build();

                EncryptedJWT jwt = getEncryptedJWT(keyId, jwtClaims);
                jwt.encrypt(new RSAEncrypter((RSAPublicKey) keyStore.getPublicKey(keyId)));

                return ConvertTo.jsonString(new LinkedHashMap<>() {{
                    put("mfa_token", jwt.serialize());
                    put("token_type", TOKEN_TYPE_MFA);
                }});
            }
            authentication.setAuthenticated(false);
            throw new ResponseStatusException(HttpStatusCode.valueOf(HttpStatus.UNAUTHORIZED.value()));
        } catch (Exception e) {
            log.error("Error Creating the Token: " + e.getMessage());

            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, UNAUTHORIZED);
        }
    }
     */

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
            log.error("Invalid token: " + e.getMessage());
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
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "UnAuthorised");
        }
        return null;
    }

}