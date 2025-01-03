package com.sds.authorization.server.dto;


/**
 * @author joseph.kibe
 * Created On 03/01/2025 08:57
 **/

public record ChangePasswordRequest(String oldPass, String newPass) {
}
