package com.sds.authorization.server.io.kafka;


import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.context.annotation.Configuration;

/**
 * @author joseph.kibe
 * Created On 11/12/2024 11:06
 **/

@Configuration
public class KafkaEventStream {

    private final StreamBridge streamBridge;

    public KafkaEventStream(StreamBridge streamBridge) {
        this.streamBridge = streamBridge;
    }

    public void publishEvent(String topic, String data) {
        streamBridge.send(topic, data);
    }
}
