package com.sds.authorization.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.repo.UserRepository;
import com.sds.authorization.server.repo.UserTokenIdRepository;
import com.sds.authorization.server.security.RSAKeyGenerator;
import com.sds.authorization.server.service.NotificationService;
import com.sds.authorization.server.service.PasswordResetService;
import com.sds.authorization.server.utility.SdsObjMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Optional;

@SpringBootTest
@Slf4j
class AuthorizationServiceApplicationTests {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private NotificationService notificationService;
    @Autowired
    private UserTokenIdRepository userTokenIdRepository;

    @Autowired
    PasswordResetService passwordResetService;

    @Test
    void contextLoads() {
    }

    @Test
    void updatingUserToken(){
        userTokenIdRepository.updateUserTokenIdStatus("xx", "LL", "iii");
    }

    @Test
    void testPreventConsecutove() {
        log.info("PASSOWRD RESET {}:", passwordResetService.hasConsecutiveSequence( "James@299",3));
    }

    @Test
    void testFetchUser(){
      Optional<User> userOptional = userRepo.findByEmail("jose@gmail.com");
        Assertions.assertFalse(userOptional.isEmpty());
        log.info(" -----> {} {}",userOptional.get().getRole(),new SdsObjMapper<>(userOptional.get(), JsonNode.class).get().asText());
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

    @Test
    void email(){
        try {
            notificationService.sendEmailNotification("--", "Test", "MYEMAIL", List.of("josewambugu25@gmail.com").toArray(new String[0]));

            Thread.sleep(10000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
