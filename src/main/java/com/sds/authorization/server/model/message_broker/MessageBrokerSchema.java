package com.sds.authorization.server.model.message_broker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;

import java.util.List;

/**
 * @author joseph.kibe
 * Created On 06/11/2024 13:17
 **/

@Getter
@Setter
@AllArgsConstructor
@Builder
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder(alphabetic = true)
public class MessageBrokerSchema {
    private String notificationRef;
    private String notificationChannel;
    private String clientId;
    private int count;
    private long delay;
    private String url;
    private String contentType;
    @JsonProperty("data")
    private Object data;
    private Metadata metadata;
    private String signature;

    @Getter
    @Setter
    @AllArgsConstructor
    @Builder
    @NoArgsConstructor
    public static class Authorization {
        private String key;
        private String value;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @Builder
    @NoArgsConstructor
    public static  class Http{
        List<Authorization> authorizations;
        String url;
        Object request;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @Builder
    @NoArgsConstructor
    public static  class SMS{
        List<String> recipients;
        String message;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @Builder
    @NoArgsConstructor
    public static class Email {
        Authorization authorization;
        String subject;
        List<String> recipients;
        String body;
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @Builder
    @NoArgsConstructor
    public static class Metadata {
        private String origin;
        private String timestamp;
    }
}
