package com.sds.authorization.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.repo.UserRepository;
import com.sds.authorization.server.security.RSAKeyGenerator;
import com.sds.authorization.server.utility.SdsObjMapper;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.weaver.patterns.IToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.Assert;

import java.util.Optional;

@SpringBootTest
@Slf4j
class AuthorizationServiceApplicationTests {

    @Autowired
    private UserRepository userRepo;

    @Test
    void contextLoads() {
    }

    @Test
    void testFetchUser(){
      Optional<User> userOptional = userRepo.findByEmailOrUsername("jose@gmail.com", "jose@gmail.com");
        Assertions.assertFalse(userOptional.isEmpty());
        log.info(" -----> {} {}",userOptional.get().getRoles(),new SdsObjMapper<>(userOptional.get(), JsonNode.class).get().asText());
    }

    @Test
    void generateToken(){
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator();

        log.info("pubKey: {}",rsaKeyGenerator.base64EncryptedPrivateKey("test"));
        log.info("pvtKey: {}",rsaKeyGenerator.base64EncryptedPublicKey("test"));
    }


    @Test
    void genJson(){
        try {
            log.info("------- {}",new ObjectMapper().writeValueAsString(new OauthClientDetails()));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
