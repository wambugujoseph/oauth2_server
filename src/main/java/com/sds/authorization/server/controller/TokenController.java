package com.sds.authorization.server.controller;

import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.TokenError;
import com.sds.authorization.server.model.UnsuccessfulResponse;
import com.sds.authorization.server.model.token.ClientLoginRequest;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.service.TokenService;
import lombok.extern.slf4j.Slf4j;
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
    @CrossOrigin
    public ResponseEntity<Object> getAuthToken(@RequestParam Map<String, String> tokenRequest) {
        log.info("Request {}", tokenRequest);
        try {
            String state = tokenRequest.get("state");
            log.info("Token State: {}", state);
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
                            tokenRequest.getOrDefault("mfa_code", ""),
                            tokenRequest.getOrDefault("code_verifier", ""),
                            tokenRequest.getOrDefault("code", ""),
                            tokenRequest.getOrDefault("redirect_uri", "")
                    )
            );

            if (token != null) {
                if (token.error() != null) {
                    return ResponseEntity.badRequest().body(token.error());
                } else if (token.mfaToken() == null && token.accessToken() == null) {
                    HttpHeaders httpHeaders = new HttpHeaders();
                    httpHeaders.setLocation(URI.create(token.redirectUri() + "?code=" + token.code() + "&code_challenge=" + token.codeChallenge()+ "&state=" + state));
                    ResponseEntity<Object> response = ResponseEntity.status(302).headers(httpHeaders).build();
                    log.info("Response Header {}", response);
                    return response;

                } else {
                    return ResponseEntity.ok(token);
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
    @CrossOrigin
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
            log.info("Request {}", authorizeRequest);

            Token token = tokenService.processAuthorizationRequest(clientLoginRequest);
            if (token.error() != null) {
                return ResponseEntity.badRequest().body(token.error());
            } else {
                return ResponseEntity.ok(token);
            }

        } catch (Exception e) {
            log.info(e.getMessage(), e);
            return ResponseEntity.status(500).body(TokenError.builder()
                    .error(UnsuccessfulResponse.server_error)
                    .errorDescription("Unknown error occurred")
                    .build());
        }

    }

    @GetMapping(value = "/api/v1/tokeninfo", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
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
