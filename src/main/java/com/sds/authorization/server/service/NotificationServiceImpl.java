package com.sds.authorization.server.service;


import com.google.common.cache.Cache;
import com.sds.authorization.server.configuration.AppProps;
import com.sds.authorization.server.io.kafka.KafkaEventStream;
import com.sds.authorization.server.model.message_broker.MessageBrokerSchema;
import com.sds.authorization.server.security.CheckSumValidator;
import com.sds.authorization.server.utility.InMemCache;
import com.sds.authorization.server.utility.SdsObjMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.UUID;

/**
 * @author joseph.kibe
 * Created On 11/12/2024 22:39
 **/

@Slf4j
@Service
public class NotificationServiceImpl implements NotificationService {

    private final Cache<String, Object> cache;
    private final AppProps config;
    private final KafkaEventStream kafkaEventStream;

    public NotificationServiceImpl(AppProps props, KafkaEventStream kafkaEventStream) {
        this.config = props;
        this.kafkaEventStream = kafkaEventStream;
        this.cache = new InMemCache().getNotificationCache();
    }

    @Override
    public void sendSmsNotification(String id, String body, String subject, String[] recipient, String clientId) {

        try {
            MessageBrokerSchema brokerSchema = MessageBrokerSchema.builder()
                    .notificationRef(UUID.nameUUIDFromBytes(("GLOBAL-SMS" + id + LocalDateTime.now().getHour()).getBytes(StandardCharsets.UTF_8)).toString())
                    .clientId(getClientId(clientId))
                    .notificationChannel("SMS")
                    .count(1)
                    .delay(0)
                    .contentType(MediaType.TEXT_PLAIN_VALUE)
                    .data(MessageBrokerSchema.SMS.builder()
                            .recipients(Arrays.stream(recipient).toList())
                            .message(body)
                            .build())
                    .metadata(MessageBrokerSchema.Metadata.builder()
                            .origin("GLOBAL-API")
                            .timestamp(Timestamp.valueOf(LocalDateTime.now()).toString())
                            .build())
                    .build();
            String dataJsonStr = SdsObjMapper.jsonString(brokerSchema);
            String signature = new CheckSumValidator().getMacSha256Signature(dataJsonStr, config.brokerKey());
            brokerSchema.setSignature(signature);
            kafkaEventStream.publishEvent("PUSH-NOTIFICATION", SdsObjMapper.jsonString(brokerSchema));
        } catch (final Exception e) {
            log.error(e.getMessage(), e);// exception to catch the errors
            log.error("Sms Sending Failed"); // failed
        }
    }

    @Override
    public void sendEmailNotification(String id, String body, String subject, String[] recipient, String clientId) {
        try {
            MessageBrokerSchema brokerSchema = MessageBrokerSchema.builder()
                    .notificationRef(UUID.nameUUIDFromBytes(("AUTH-SERVER-EMAIL" + id + LocalDateTime.now().getHour()).getBytes(StandardCharsets.UTF_8)).toString())
                    .clientId(getClientId(clientId))
                    .notificationChannel("EMAIL")
                    .count(1)
                    .delay(0)
                    .contentType(MediaType.TEXT_HTML_VALUE)
                    .data(MessageBrokerSchema.Email.builder()
                            .subject(subject)
                            .recipients(Arrays.stream(recipient).toList())
                            .body(body)
                            .build())
                    .metadata(MessageBrokerSchema.Metadata.builder()
                            .origin("AUTH-SERVER")
                            .timestamp(Timestamp.valueOf(LocalDateTime.now()).toString())
                            .build())
                    .build();
            String dataJsonStr = SdsObjMapper.jsonString(brokerSchema);
            String signature = new CheckSumValidator().getMacSha256Signature(dataJsonStr, config.brokerKey());
            brokerSchema.setSignature(signature);
            kafkaEventStream.publishEvent("PUSH-NOTIFICATION", SdsObjMapper.jsonString(brokerSchema));
        } catch (final Exception e) {
            log.error(e.getMessage(), e);// exception to catch the errors
            log.error("Email Sending Failed"); // failed
        }
    }

    private String getClientId(String client) {

        if (client != null){
            if (client.equalsIgnoreCase("9") || client.equalsIgnoreCase("12")){
                return "UPESI";
            }
        }

        return "SWITCHLINK";
    }

    public static String EmailTemplate = """
            <tr>
                <td style="padding:26.25pt;box-sizing:border-box; color: rgb(61, 72, 82); border-width:1px">
                    <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                        <span>Hi%s,</span>
                    </p>
                    <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                        <span>%s</span>
                    </p>
                </td>
            </tr>
            """;

    public static String PasswordResetEmailTemplate = """
            <tr>
                <td style="padding:26.25pt;box-sizing:border-box; color: rgb(61, 72, 82); border-width:1px">
                    <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                        <span>Hi%s,</span>
                    </p>
                    <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                        <span>%s</span>
                    </p>
                </td>
            </tr>
            <tr>
                <td align="center">
                    <a href="%s"  style=" color: #FFF;border-radius:3px; text-decoration:none;background-color:#22BC66;border-top:10px solid #22BC66;border-right: 18px solid #22BC66;border-bottom: 10px solid #22BC66;border-left: 18px solid #22BC66;" class="f-fallback button button--green" target="_blank">Reset your password</a>
                </td>
            </tr>
            """;
}
