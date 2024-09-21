package com.sds.authorization.server.utility;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * @author samwel.wafula
 * Created on 21/09/2024
 * Time 09:20
 * Project SDS-AuthServer
 */
@Component
@Data
public class AppConfig {

    @Value("${app.smtp_host}")
    private String mailHost;
    @Value("${app.username}")
    private String mailUsername;
    @Value("${app.password}")
    private String mailPassword;
}
