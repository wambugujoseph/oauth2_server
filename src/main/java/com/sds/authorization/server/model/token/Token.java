package com.sds.authorization.server.model.token;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 7:56 AM
 */


public record Token (
        String accessToken,
        String refreshToken,
        String tokenType,
        long expire_in,
        String scope
) {
}
