package com.sds.authorization.server.model.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 7:56 AM
 */


@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Token (
        String accessToken,
        String refreshToken,
        String tokenType,
        long expire_in,
        String scope
) {
}
