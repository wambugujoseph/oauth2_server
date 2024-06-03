package com.sds.authorization.server.model;

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
public class CustomResponse {

    String responseCode;
    String responseDesc;
}

