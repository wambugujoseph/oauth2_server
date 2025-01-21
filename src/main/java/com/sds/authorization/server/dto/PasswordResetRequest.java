package com.sds.authorization.server.dto;


/**
 * @author joseph.kibe
 * Created On 03/01/2025 08:57
 **/

public record PasswordResetRequest(String userId,
                                   String responseType,
                                   String clientId,
                                   String redirectUrl,
                                   String state,
                                   String codeChallenge,
                                   String codeChallengeMethod,
                                   String product
) {
}
