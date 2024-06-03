package com.sds.authorization.server.utility;

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
}
