package com.sds.authorization.server.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

/**
 * @author Joseph Kibe
 * Created on May 31, 2024.
 * Time 5:06 PM
 */

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CustomResponse {

    @JsonProperty("response_code")
    String responseCode;
    @JsonProperty("response_desc")
    String responseDesc;
    Object data;
    @JsonProperty("error")
    private UnsuccessfulResponse error;
    @JsonProperty("error_description")
    private String errorDescription;
}

