package com.sds.authorization.server.security;

import lombok.Getter;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author Joseph Kibe
 * Created on May 19, 2023.
 * Time 10:57 AM
 */

@Getter
public class EncDecKey {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String keyId;

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
