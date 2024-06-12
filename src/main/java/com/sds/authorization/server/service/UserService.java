package com.sds.authorization.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 12:07 AM
 */

@Service
@Slf4j
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public void createUser(UserCreatedDto userCreatedDto){
        try {
            User user = User.builder()
                    .username(userCreatedDto.username())
                    .email(userCreatedDto.email())
                    .userId(("USR-"+Long.toString(Long.parseLong(new Date().getTime() +""+new Random().nextInt(9)), 36)).toUpperCase())
                    .password(new BCryptPasswordEncoder(
                            BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8))).encode(userCreatedDto.password()))
                    .enabled(true)
                    .accountNonExpired(true)
                    .credentialsNonExpired(true)
                    .accountNonLocked(true)
                    .roles(List.of(Role.builder().name(userCreatedDto.category()).build()))
                    .build();

            log.info("NEW user {} ", new ObjectMapper().writeValueAsString(user));

            userRepository.save(user);

        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
        }
    }
}
