package com.sds.authorization.server.model.token;


/**
 * @author joseph.kibe
 * Created On 13/12/2024 11:20
 **/


public record ClientLoginRequest(
        String responseType,
        String clientId,
        String redirectUri,
        String scope,
        String codeChallenge,
        String codeChallengeMethod,
        String username,
        String password
) {
}
