package com.sds.authorization.server.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

/**
 * @author joseph.kibe
 * Created On 15/12/2024 20:24
 **/

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenError {
    @JsonProperty("error")
    private UnsuccessfulResponse error;
    @JsonProperty("error_description")
    private String errorDescription;
    @JsonProperty("error_uri")
    private String errorUri;
}
