package com.sds.authorization.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sds.authorization.server.dto.ChangePasswordRequest;
import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.UnsuccessfulResponse;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Optional;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.sds.authorization.server.model.UnsuccessfulResponse.unauthorized_client;
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
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, NotificationService emailNotificationService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.emailNotificationService = emailNotificationService;
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder(
                BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8)));
        ;
    }


    public User getActiveUserByEmail(String email) {
        return userRepository.findByEmailAndStatus(email, "ACTIVE").orElse(null);
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public void lockeUserAccountFailedLogin(String email) {
        userRepository.lockeUserAccountFailedLogin(email);
    }

    public void recordUserFailedLoginAttempt(String email) {
        userRepository.recordUserFailedLoginAttempt(email);
    }

    public CustomResponse createUser(UserCreatedDto userCreatedDto) {
        String randomPassword = generateRandomPassword(8);
        try {
            //Check Duplicate
            Optional<User> optionalUser = userRepository.findByEmail(userCreatedDto.email());
            if (optionalUser.isPresent()) {
                return CustomResponse.builder()
                        .responseCode("400")
                        .responseDesc("User already exist")
                        .build();
            }
            log.info("user dto {}", userCreatedDto);
            User user = User.builder()
                    .username(userCreatedDto.username())
                    .email(userCreatedDto.email())
                    .phoneNumber(userCreatedDto.phoneNumber())
                    .userId(("USR-" + Long.toString(Long.parseLong(new Date().getTime() + "" + new Random().nextInt(9)), 36)).toUpperCase())
                    .password(new BCryptPasswordEncoder(
                            BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8))).encode(randomPassword))
                    .status("ACTIVE")
                    .role(Role.builder().name(userCreatedDto.category()).build())
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

    public CustomResponse updateUser(UserCreatedDto createdDto) {
        Optional<User> optionalUser = userRepository.findByEmail(createdDto.email());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.setPhoneNumber(createdDto.phoneNumber());
            user.setPassword(new BCryptPasswordEncoder(
                    BCryptPasswordEncoder.BCryptVersion.$2A, 11, new SecureRandom("XXL".getBytes(StandardCharsets.UTF_8))).encode(createdDto.password()));
            userRepository.save(user);
            return CustomResponse.builder()
                    .responseCode("200")
                    .responseDesc("User successfully update")
                    .build();
        } else {
            return CustomResponse.builder()
                    .responseCode("400")
                    .responseDesc("User already exist")
                    .build();
        }
    }

    public CustomResponse changePassword(ChangePasswordRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String regExpn = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";
        Pattern pattern = Pattern.compile(regExpn, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(request.newPass());

        if (authentication.isAuthenticated() && authentication.getPrincipal() instanceof User user) {
            if (matcher.matches()) {
                if (bCryptPasswordEncoder.matches(request.oldPass(), user.getPassword())) {
                    if (!bCryptPasswordEncoder.matches(request.newPass(), user.getPassword())) {
                        userRepository.updateUserPassword(user.getEmail(), bCryptPasswordEncoder.encode(request.newPass()));
                        //TODO push lock account notification in case the change was not initiate by the account owner
                        return CustomResponse.builder()
                                .responseCode("200")
                                .responseDesc("Password was successfully updated")
                                .build();

                    } else {
                        return CustomResponse.builder()
                                .error(UnsuccessfulResponse.invalid_request)
                                .errorDescription("New password cannot be similar to the old password")
                                .build();
                    }
                } else {
                    return CustomResponse.builder()
                            .error(UnsuccessfulResponse.invalid_request)
                            .errorDescription("Invalid password")
                            .build();
                }
            } else {
                return CustomResponse.builder()
                        .error(UnsuccessfulResponse.invalid_request)
                        .errorDescription("New password doest meet the password strength requirement")
                        .build();
            }
        }
        return CustomResponse.builder()
                .error(UnsuccessfulResponse.unauthorized_client)
                .errorDescription("User not authenticated")
                .build();
    }

}
