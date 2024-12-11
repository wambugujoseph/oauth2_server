package com.sds.authorization.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import static com.sds.authorization.server.security.PasswordGenerator.generateRandomPassword;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 12:07 AM
 */

@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final NotificationService emailNotificationService;

    public UserService(UserRepository userRepository, NotificationService emailNotificationService) {
        this.userRepository = userRepository;
        this.emailNotificationService = emailNotificationService;
    }

    public CustomResponse createUser(UserCreatedDto userCreatedDto) {
        String randomPassword = generateRandomPassword(8);
        try {
            //Check Duplicate
            Optional<User> optionalUser = userRepository.findByEmailOrUsername(userCreatedDto.email(), userCreatedDto.username());
            if (optionalUser.isPresent()) {
                return CustomResponse.builder()
                        .responseCode("400")
                        .responseDesc("User already exist")
                        .build();
            }
            log.info("user dto {}",userCreatedDto);
            User user = User.builder()
                    .username(userCreatedDto.username())
                    .email(userCreatedDto.email())
                    .phoneNumber(userCreatedDto.phoneNumber())
                    .userId(("USR-" + Long.toString(Long.parseLong(new Date().getTime() + "" + new Random().nextInt(9)), 36)).toUpperCase())
                    .password(new BCryptPasswordEncoder(
                            BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8))).encode(randomPassword))
                    .enabled(true)
                    .accountNonExpired(true)
                    .credentialsNonExpired(true)
                    .accountNonLocked(true)
                    .isKycVerified(userCreatedDto.isKycVerified())
                    .roles(List.of(Role.builder().name(userCreatedDto.category()).build()))
                    .build();

            log.info("NEW user {} ", new ObjectMapper().writeValueAsString(user));
            userRepository.save(user);



            return CustomResponse.builder()
                    .responseCode("200")
                    .responseDesc("User created Successfully")
                    .build();

        } catch (
                JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return CustomResponse.builder()
                    .responseCode("500")
                    .responseDesc("Internal server error")
                    .build();
        }
    }

    public CustomResponse updateUser(UserCreatedDto createdDto){
        Optional<User> optionalUser = userRepository.findByEmailOrUsername(createdDto.email(), createdDto.username());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.setPhoneNumber(createdDto.phoneNumber());
            user.setKycVerified(createdDto.isKycVerified());
            user.setPassword(new BCryptPasswordEncoder(
                    BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8))).encode(createdDto.password()));
            userRepository.save(user);
            return CustomResponse.builder()
                    .responseCode("200")
                    .responseDesc("User successfully update")
                    .build();
        }else {
            return CustomResponse.builder()
                    .responseCode("400")
                    .responseDesc("User already exist")
                    .build();
        }
    }
}
