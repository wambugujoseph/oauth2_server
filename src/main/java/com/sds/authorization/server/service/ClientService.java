package com.sds.authorization.server.service;

import com.sds.authorization.server.dto.ClientCreateDto;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.repo.OauthClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.RandomStringGenerator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Optional;
import java.util.Random;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 10:00 AM
 */

@Service
@Slf4j
public class ClientService {


    private final Random random;
    private OauthClientRepository oauthClientRepository;

    public ClientService(OauthClientRepository oauthClientRepository) {
        this.oauthClientRepository = oauthClientRepository;
        this.random = new Random();
    }

    public OauthClientDetails createOauthClientDetails(ClientCreateDto clientCreateDto) {

        try {
            RandomStringGenerator pwdGen = new RandomStringGenerator.Builder().selectFrom("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ123456789._+=@%|,".toCharArray()).withinRange(50, 50).get();
            RandomStringGenerator pwdGen2 = new RandomStringGenerator.Builder().selectFrom("bcdfghjklmnpqrstvwxyz123456789".toCharArray()).withinRange(30, 50).get();
            String clientID = ("ct-" + Long.toString(Long.parseLong(new Date().getTime() + "" + random.nextInt(1000, 1999)), 36) +
                    "-" + pwdGen2.generate(15));
            String clientSecret = pwdGen.generate(50);

            OauthClientDetails clientDetails = OauthClientDetails.builder()
                    .clientId(clientID)
                    .clientSecret(new BCryptPasswordEncoder(
                            BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom(String.valueOf(random.nextInt(10,99)).getBytes(StandardCharsets.UTF_8))).encode(clientSecret))
                    .webServerRedirectUri(clientCreateDto.webServerRedirectUri())
                    .scope(clientCreateDto.scope())
                    .accessTokenValidity(clientCreateDto.accessTokenValidity())
                    .refreshTokenValidity(clientCreateDto.refreshTokenValidity())
                    .resourceIds(clientCreateDto.resourceIds())
                    .authorizedGrantTypes(clientCreateDto.authorizedGrantTypes())
                    .authorities(clientCreateDto.authorities())
                    .additionalInformation(clientCreateDto.additionalInformation())
                    .autoApprove(String.valueOf(clientCreateDto.autoapprove()))
                    .numberUser(clientCreateDto.numberUser())
                    .username("TEST")
                    .applicationName(clientCreateDto.applicationName())
                    .build();
            OauthClientDetails oauthClientDetails = oauthClientRepository.save(clientDetails);
            oauthClientDetails.setClientSecret(clientSecret);
            return oauthClientDetails;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public OauthClientDetails getOauthClientDetails(String clientId){
        return oauthClientRepository.findById(clientId).orElse(null);
    }
}
