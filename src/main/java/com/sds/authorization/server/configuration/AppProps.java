package com.sds.authorization.server.configuration;

import org.apache.kafka.common.protocol.types.Field;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Joseph Kibe
 * Created on May 25, 2024.
 * Time 4:26 PM
 */

@ConfigurationProperties(prefix = "app")
public record AppProps(
        String smtpHost,
        String smtpPort,
        String emailUsername,
        String emailPassword,
        boolean isAppLive,
        String pubKey,
        String pvtKey,
        String brokerKey,
        String env,
        String baseUrl,
        String cipher
) {
}
