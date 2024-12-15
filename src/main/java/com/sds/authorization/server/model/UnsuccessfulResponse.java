package com.sds.authorization.server.model;


/**
 * @author joseph.kibe
 * Created On 15/12/2024 20:15
 **/

public enum UnsuccessfulResponse {
    invalid_request,
    invalid_client,
    invalid_grant,
    invalid_scope,
    unauthorized_client,
    unsupported_grant_type,
    server_error
}
