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
    public void sendSmsNotification(String id, String body, String subject, String[] recipient) {

        try {
            MessageBrokerSchema brokerSchema = MessageBrokerSchema.builder()
                    .notificationRef(UUID.nameUUIDFromBytes(("GLOBAL-SMS" + id + LocalDateTime.now().getHour()).getBytes(StandardCharsets.UTF_8)).toString())
                    .clientId("SWITCHLINK")
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
    public void sendEmailNotification(String id, String body, String subject, String[] recipient) {
        body = String.format(EmailTemplate, "", body);
        try {
            MessageBrokerSchema brokerSchema = MessageBrokerSchema.builder()
                    .notificationRef(UUID.nameUUIDFromBytes(("AUTH-SERVER-EMAIL" + id + LocalDateTime.now().getHour()).getBytes(StandardCharsets.UTF_8)).toString())
                    .clientId("SWITCHLINK")
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

    public static String EmailTemplate = """
            <div style="display:grid; justify-content: center;">
                <div></div>
                <table style="width:100%%;border-radius: 25px;">
                    <tbody>
                    <tr height="32" style="height:32px">
                        <td></td>
                    </tr>
                    <tr align='center'>
                        <td style="width:100%%;padding:0;border-style:solid none;border-top-width:1pt;border-bottom-width:1pt;border-top-color:#EDEFF2;border-bottom-color:#EDEFF2;box-sizing:border-box;">
                            <div align="center">
                                <table cellpadding="0" cellspacing="0"
                                       style="background-color:white;width:500.5pt;box-sizing:border-box; border-color:#A0A0A0 #A0A0A0 #ffffff #A0A0A0; border-width:1px">
                                    <tbody>
                                    <tr style="background-color:#7c74cc;">
                                        <td style="padding:18.75pt 0;">
                                            <p align="center" style="font-size:11pt; text-align:center;margin:0;">
                                        <span>
                                            <a style="text-decoration:none" data-auth="NotApplicable" data-linkindex="3"
                                               href="https://asgard.slafrica.net:9810/"
                                               rel="noopener noreferrer" target="_blank">
                                                <b><span style="color:#000000;font-size:16.5pt;">Switch-Bridge</span></b>
                                            </a>
                                        </span>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding:26.25pt;box-sizing:border-box; color: rgb(61, 72, 82); border-width:1px">
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                                                <span>Hi%s,</span>
                                            </p>
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt; font-size:11pt;">
                                                <span>%s</span>
                                            </p>
                                            <p style="margin-top:0;box-sizing:border-box;line-height:18.0pt;">
                                            <span style="font-family: &quot;Segoe UI&quot;, sans-serif, serif, EmojiFont;">Kind Regards,<br
                                                    aria-hidden="true">Switch-Bridge</span>
                                            </p>
                                            <p style="margin-top:0; box-sizing:border-box; text-align: center;">
                                                        <span style="color: rgb(174, 174, 174); font-size:9pt; text-align: center;">
                                                           </span>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr align='center'>
                                        <td style="background-color:#cccccc; padding:0;box-sizing:border-box;">
                                            <div align="center">
                                                <table border="0" cellpadding="0" cellspacing="0"
                                                       style="width:427.5pt;box-sizing:border-box;">
                                                    <tbody>
                                                    <tr></tr>
                                                    <td style="padding:10pt;box-sizing:border-box;">
                                                        <p align="center"
                                                           style="text-align:center;margin-top:0;box-sizing:border-box;line-height:18.0pt;">
                                                            <span style="font-family: &quot;Segoe UI&quot;, sans-serif, serif, EmojiFont;">
                                                            ©2024. All rights reserved.</span>
                                                               <hr/>
                                                             CONFIDENTIALITY NOTICE: This message (and any attachment) is confidential and intended for the sole use of the individual or entity to which it 
                                                             is addressed. If you are not the intended recipient, you must not review, retransmit, convert to hard-copy, copy, use or disseminate this email or any of its attachments. If you received this email in error, please notify the sender immediately and delete it. This notice is automatically appended to all Internet email.
                                                            
                                                        </p></td>
                                                    </tr>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </td>
                                    </tr>
                                    </tbody>
                                </table>
                            </div>
                        </td>
                    </tr>
                    <tr height="32" style="height:32px">
                        <td></td>
                    </tr>
                    </tbody>
                </table>
            </div>
            """;
}
