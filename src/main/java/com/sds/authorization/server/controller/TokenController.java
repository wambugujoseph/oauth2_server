package com.sds.authorization.server.controller;

import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.token.Token;
import com.sds.authorization.server.model.token.TokenRequest;
import com.sds.authorization.server.security.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 7:59 AM
 */

@RestController
@Slf4j
public class TokenController {

    @Autowired
    private TokenService tokenService;

    @RequestMapping(value = "/api/v1/oauth/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, method = RequestMethod.POST)
    public ResponseEntity<?> getAuthToken(@RequestParam Map<String, String> tokenRequest) {
        try {
            Token token = tokenService.tokenGeneratorHandler(
                    new TokenRequest(
                            tokenRequest.getOrDefault("client_id", ""),
                            tokenRequest.getOrDefault("grant_type", ""),
                            tokenRequest.getOrDefault("client_secret", ""),
                            tokenRequest.getOrDefault("audience", ""),
                            tokenRequest.getOrDefault("username", ""),
                            tokenRequest.getOrDefault("password", "")
                    )
            );
            if (token != null) {
                return ResponseEntity.ok(token);
            }
            return ResponseEntity.status(401).body(CustomResponse.builder()
                    .responseCode("401")
                    .responseDesc("UnAuthorized"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @RequestMapping(value ="/api/v1/tokeninfo", consumes =MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE, method = RequestMethod.GET)
    public ResponseEntity<?> tokenInfo(@RequestParam("access_token") String accessToken ){

        try {
            return ResponseEntity.ok(tokenService.getTokenInfo(accessToken));
        } catch (Exception e){
            return ResponseEntity.status(401).body(CustomResponse.builder()
                    .responseCode("401")
                    .responseDesc("UnAuthorized"));
        }
    }
}
