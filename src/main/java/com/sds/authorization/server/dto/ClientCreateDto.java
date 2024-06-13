package com.sds.authorization.server.dto;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 10:03 AM
 */

public record ClientCreateDto(
        String webServerRedirectUri,
        String scope,
        int accessTokenValidity,
        int refreshTokenValidity,
        String authorizedGrantTypes,
        String authorities,
        String additionalInformation,
        String applicationName,
        String resourceIds,
        int numberUser,
        boolean autoapprove
        ) {
}
