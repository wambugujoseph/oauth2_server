package com.sds.authorization.server.controller;

import com.sds.authorization.server.model.AuthorizationCodeChallenge;
import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.token.ClientLoginRequest;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.service.TokenService;
import com.sds.authorization.server.utility.SdsObjMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 7:59 AM
 */

@RestController
@Slf4j
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping(value = "/api/v1/oauth/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Object> getAuthToken(@RequestParam Map<String, String> tokenRequest) {
        try {
            Token token = tokenService.tokenGeneratorHandler(
                    new TokenRequest(
                            tokenRequest.getOrDefault("client_id", ""),
                            tokenRequest.getOrDefault("grant_type", ""),
                            tokenRequest.getOrDefault("client_secret", ""),
                            tokenRequest.getOrDefault("audience", ""),
                            tokenRequest.getOrDefault("username", ""),
                            tokenRequest.getOrDefault("password", ""),
                            tokenRequest.getOrDefault("refresh_token", ""),
                            tokenRequest.getOrDefault("mfa_token", ""),
                            tokenRequest.getOrDefault("mfa_code", "")
                    )
            );

            if (token != null) {
                if (token.mfaToken() == null && token.accessToken() == null) {
                    HttpHeaders httpHeaders = new HttpHeaders();
                    httpHeaders.setLocation(URI.create(token.redirectUri() + "#code=" + token.code() + "&code_challenge=" + token.codeChallenge()));
                    return ResponseEntity.status(302).headers(httpHeaders).build();

                } else if (token.verified()) {
                    return ResponseEntity.ok(token);
                } else {
                    HttpHeaders httpHeaders = new HttpHeaders();
                    httpHeaders.add("Location", "/client/sds-core/api/v1/specialist/" + tokenRequest.get("username"));
                    return new ResponseEntity<>(token, httpHeaders, HttpStatus.OK);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return ResponseEntity.status(401).body(CustomResponse.builder()
                .responseCode("401")
                .responseDesc("UnAuthorized").build());
    }

    @PostMapping(value = "/api/v1/oauth/authorize", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> loginClient(@RequestParam Map<String, String> authorizeRequest) {

        try {
            ClientLoginRequest clientLoginRequest = new ClientLoginRequest(
                    authorizeRequest.get("response_type"),
                    authorizeRequest.get("client_id"),
                    authorizeRequest.get("redirect_uri"),
                    authorizeRequest.get("scope"),
                    authorizeRequest.get("code_challenge"),
                    authorizeRequest.get("code_challenge_method"),
                    authorizeRequest.get("username"),
                    authorizeRequest.get("password")
            );

            Token token = tokenService.processAuthorizationRequest(clientLoginRequest);

            log.info("Request {}", SdsObjMapper.jsonString(clientLoginRequest));
            return ResponseEntity.ok(token);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @GetMapping(value = "/api/v1/tokeninfo", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> tokenInfo(@RequestParam("access_token") String accessToken) {

        try {
            return ResponseEntity.ok(tokenService.getTokenInfo(accessToken));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(CustomResponse.builder()
                    .responseCode("401")
                    .responseDesc("UnAuthorized"));
        }
    }
}
