package com.sds.authorization.server.security;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.sds.authorization.server.configuration.AppProps;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;

/**
 * @author Joseph Kibe
 * Created on May 12, 2023.
 * Time 10:24 AM
 * <p>
 * The Key Store uses Google commos cache to hold Keys in memory
 */

@Component
@Slf4j
public class KeyStore {
    // Key Cache
    private final Cache<String, EncDecKey> cache;

    @Autowired
    private AppProps props;

    public KeyStore() {
        this.cache = getCache();
    }

    public PublicKey getPublicKey(String keyId) {
        return keyCache(keyId).getPublicKey();
    }

    public PrivateKey getPrivateKey(String keyId) {
        return keyCache(keyId).getPrivateKey();
    }

    public void addToCache(EncDecKey encDecKey) {
        cache.put(encDecKey.getKeyId(), encDecKey);
    }

    /**
     * Act as the key Cache Layer The key Are held InMemory since the number of Keys is small
     *
     * @param keyId Unique identifier
     * @return Record
     */
    private EncDecKey keyCache(String keyId) {
        EncDecKey encDecKey = cache.getIfPresent(keyId);
        if (encDecKey != null) {
            return encDecKey;
        } else {
            return findEncryptionKeys(keyId);
        }
    }

    public EncDecKey findEncryptionKeys(String keyId) {
        try {
            String pvtKeyStr = props.pvtKey();
            String pubKeyStr = props.pubKey();
            PublicKey pubKey = RSAKeyGenerator.getPublicKey(props.cipher(), pubKeyStr);
            PrivateKey pvtKey = RSAKeyGenerator.getPrivateKey(props.cipher(), pvtKeyStr);
            EncDecKey encDecKey = new EncDecKey();
            encDecKey.setKeyId(keyId);
            encDecKey.setPublicKey(pubKey);
            encDecKey.setPrivateKey(pvtKey);
            addToCache(encDecKey);

            return encDecKey;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    private Cache<String, EncDecKey> getCache() {
        return CacheBuilder
                .newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS).build();
    }
}