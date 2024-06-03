package com.sds.authorization.server.security;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;

/**
 * @author Joseph Kibe
 * Created on May 16, 2023.
 * Time 6:17 PM
 */

@Slf4j
public class RSAKeyGenerator {
    private static final SecureRandom rng = new SecureRandom(SecureRandom.getSeed(100));
    private static final String AES = "AES/CBC/PKCS5Padding";
    public int keySize = 2048;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    @Getter
    private String keyId;

    public RSAKeyGenerator() {
        try {
            SecureRandom secureRandom = new SecureRandom("SDS".getBytes(StandardCharsets.UTF_8));
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize, secureRandom);
            KeyPair pair = keyGen.generateKeyPair();

            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            long length = 12;
            this.keyId = generateRandomString(length);

        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

    public static PublicKey getPublicKey(String password, String publicKeyBase64StringEnc) {
        PublicKey publicKey;

        try {
            String decryptedPub = decryptWithAES(password, publicKeyBase64StringEnc);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(decryptedPub.getBytes(StandardCharsets.UTF_8)));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);

            return publicKey;
        } catch (Exception e) {
            log.warn("Failed To generated private key: " + e.getMessage());
        }

        return null;
    }

    public static PrivateKey getPrivateKey(String password, String privateKeyBase64StringEnc) {
        PrivateKey privateKey = null;

        try {
            String decryptedPvt = decryptWithAES(password, privateKeyBase64StringEnc);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(decryptedPvt.getBytes(StandardCharsets.UTF_8)));
            KeyFactory keyFactory;

            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            log.warn("Failed To generated private key: " + e.getMessage());
        }

        return privateKey;
    }

    public static String decryptWithAES(String password, String encryptedBase64Data) {
        try {
            SecretKey key = getSecretKey(password);
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, key, generateIv());
            byte[] decryptedByte = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64Data));

            return Base64.getEncoder().encodeToString(decryptedByte);
        } catch (Exception e) {
            log.warn("Failed To Decrypt Key: " + e.getMessage());
        }

        return "";
    }

    private static SecretKey getSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] salt = new byte[16];
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        return new IvParameterSpec(iv);
    }

    public String base64EncryptedPrivateKey(String password) {
        byte[] pvtKey = this.privateKey.getEncoded();

        return encryptWithAES(password, pvtKey);
    }

    public String base64EncryptedPublicKey(String password) {
        byte[] pubKey = this.publicKey.getEncoded();

        return encryptWithAES(password, pubKey);
    }

    public String encryptWithAES(String password, byte[] data) {
        try {
            SecretKey key = getSecretKey(password);
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.ENCRYPT_MODE, key, generateIv());

            byte[] cipherByte = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(cipherByte);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        return "";
    }


    private boolean useThisCharacter(char c) {
        return c >= '0' && c <= 'z' && Character.isLetterOrDigit(c);
    }

    private String generateRandomString(long length) {
        Stream<Character> randomCharStream = rng.ints(Character.MIN_CODE_POINT, Character.MAX_CODE_POINT)
                .mapToObj(i -> (char) i).filter(this::useThisCharacter).limit(length);

        return randomCharStream.collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString();
    }
}