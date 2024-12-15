package com.sds.authorization.server.model.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.sds.authorization.server.model.TokenError;

import java.util.List;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 7:56 AM
 */


@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Token(
        @JsonProperty("mfa_token")
        String mfaToken,
        @JsonProperty("access_token")
        String accessToken,
        @JsonProperty("refresh_token")
        String refreshToken,
        @JsonProperty("token_type")
        String tokenType,
        @JsonProperty("expire_in")
        long expireIn,
        List<String> roles,
        String scope,
        boolean verified,
        String code,
        String codeChallenge,
        String redirectUri,
        TokenError error
) {
}
