package com.sds.authorization.server.utility;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.util.concurrent.TimeUnit;

/**
 * @author Joseph Kibe
 * Created on June 10, 2023.
 * Time 9:57 AM
 */

public class InMemCache {

    Cache<String, Object> notificationCache;

    public Cache<String, Object> getNotificationCache() {
        this.notificationCache = CacheBuilder
                .newBuilder()
                .expireAfterWrite(30, TimeUnit.MINUTES).build();

        return notificationCache;
    }
}
