package com.sds.authorization.server.dto;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author joseph.kibe
 * Created On 06/02/2025 12:55
 **/

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class InvalidateUserTokenRequest {

    private String email;
    private String tokenId;
    private boolean fullInvalidation;
}
