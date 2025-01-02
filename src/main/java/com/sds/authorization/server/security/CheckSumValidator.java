package com.sds.authorization.server.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

/**
 * @author Joseph Kibe
 * Created on May 09, 2023.
 * Time 10:14 AM
 */

@Component
@Slf4j
public class CheckSumValidator {

    public String getMacSha256Signature(String message, String key)  {

        try {
            byte[] bytesKey = key.getBytes();
            byte[] bytesMessage = message.getBytes();

            String algorithim = "HmacSHA512";
            Mac mac = Mac.getInstance(algorithim);
            mac.init(new SecretKeySpec(bytesKey, algorithim));
            mac.update(bytesMessage);
            byte[] result = mac.doFinal();
            HexFormat hexFormat = HexFormat.of();
            return hexFormat.formatHex(result);
        } catch (Exception e) {
            log.info(e.getMessage(), e);
        }

        return "";

    }
}