package com.sds.authorization.server.dto;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 12:00 AM
 */

public record UserCreatedDto(
        String username,
        String email,
        String password,
        String phoneNumber,
        String category,
        boolean isKycVerified
) {
}
