package com.sds.authorization.server.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Joseph Kibe
 * Created on May 25, 2024.
 * Time 4:26 PM
 */

@ConfigurationProperties(prefix = "app")
public record AppProps(
    boolean isAppLive,
    String pubKey,
    String pvtKey
) {
}
