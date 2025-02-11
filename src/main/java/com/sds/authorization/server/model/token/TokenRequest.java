package com.sds.authorization.server.model.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.servlet.http.HttpServletRequest;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 8:02 AM
 */
@JsonSerialize
public record TokenRequest(
        @JsonProperty(value = "client_id", required = true)
        String clientId,
        @JsonProperty(value = "grant_type", required = true)
        String grantType,
        @JsonProperty("client_secret")
        String clientSecret,
        @JsonProperty(value = "audience", defaultValue = "-")
        String audience,
        @JsonProperty("username")
        String username,
        @JsonProperty(value = "password", defaultValue = "-")
        String password,
        @JsonProperty(value = "refresh_token", defaultValue = "-")
        String refreshToken,
        @JsonProperty(value = "mfa_token", defaultValue = "-")
        String mfaToken,
        @JsonProperty(value = "mfa_code", defaultValue = "-")
        String mfaCode,
        @JsonProperty(value = "code_verifier", defaultValue = "")
        String codeVerifier,
        @JsonProperty(value = "code", defaultValue = "")
        String code,
        @JsonProperty(value = "redirect_uri", defaultValue = "")
        String redirectUri,
        @JsonIgnore
        HttpServletRequest servletRequest
) {
}
