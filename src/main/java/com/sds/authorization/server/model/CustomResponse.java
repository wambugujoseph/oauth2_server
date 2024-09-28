package com.sds.authorization.server.model;

import com.fasterxml.jackson.annotation.JsonInclude;
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
    String responseCode;
    String responseDesc;
    Object data;
}

