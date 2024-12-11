package com.sds.authorization.server.utility;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.extern.slf4j.Slf4j;

/**
 * The Class provide a functionality to convert one object to the next
 *
 * @param <T> From Object
 * @param <N> To Object
 * @author Joseph Kibe
 * Created on May 10, 2024.
 * Time 10:55 PM
 */

@Slf4j
public class SdsObjMapper<IN, OUT> {

    private final OUT convertedToObjet;

    public SdsObjMapper(IN objectToConvert, Class<OUT> cls) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            this.convertedToObjet = objectMapper.convertValue(objectToConvert, cls);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public OUT get() {
        return this.convertedToObjet;
    }

    public static JsonNode jsonNodeFromStr(String data) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readTree(data);

        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public static String jsonString(Object objectToConvert) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(objectToConvert);

        } catch (JsonProcessingException e) {
            log.error(e.getMessage(),e);
            return null;
        }
    }
}
