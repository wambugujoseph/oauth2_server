package com.sds.authorization.server.controller;

import com.sds.authorization.server.dto.ChangePasswordRequest;
import com.sds.authorization.server.dto.PasswordResetRequest;
import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.UnsuccessfulResponse;
import com.sds.authorization.server.service.PasswordResetService;
import com.sds.authorization.server.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on June 13, 2025.
 * Time 12:03 AM
 */


@RestController
@Slf4j
public class UserController {

    private final UserService userService;
    private final PasswordResetService resetService;

    public UserController(UserService userService, PasswordResetService resetService) {
        this.userService = userService;
        this.resetService = resetService;
    }

    @PostMapping(value = "/api/v1/register/user", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<Object> createUser(@RequestBody UserCreatedDto userCreatedDto) {
        CustomResponse customResponse = userService.createUser(userCreatedDto);
        return ResponseEntity.status(Integer.parseInt(customResponse.getResponseCode())).body(customResponse);

    }

    @PutMapping(value = "/api/v1/update/user", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<Object> updateUser(@RequestBody UserCreatedDto userCreatedDto) {
        CustomResponse customResponse = userService.updateUser(userCreatedDto);
        return ResponseEntity.status(Integer.parseInt(customResponse.getResponseCode())).body(customResponse);

    }


    @PostMapping(value = "/api/v1/password_reset", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<Object> intiUserPasswordReset(@RequestBody MultiValueMap<String, String> passwordReset) {

        if (passwordReset != null) {
            PasswordResetRequest request = new PasswordResetRequest(
                    passwordReset.getFirst("email"),
                    Optional.ofNullable(passwordReset.getFirst("response_type")).orElse(""),
                    Optional.ofNullable(passwordReset.getFirst("client_id")).orElse(""),
                    Optional.ofNullable(passwordReset.getFirst("redirect_uri")).orElse(""),
                    Optional.ofNullable(passwordReset.getFirst("state")).orElse(""),
                    Optional.ofNullable(passwordReset.getFirst("code_challenge")).orElse(""),
                    Optional.ofNullable(passwordReset.getFirst("code_challenge_method")).orElse("")
            );
            CustomResponse response = resetService.initiatePasswordReset(request);

            if (response.getError() == null) {
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
        return ResponseEntity.badRequest().body(CustomResponse.builder().error(UnsuccessfulResponse.invalid_request)
                .errorDescription("Null password not allowed"));
    }

    @PutMapping(value = "/api/v1/password_reset", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<Object> updateUserPassword(@RequestBody MultiValueMap<String, String> passwordReset) {

        if (passwordReset != null) {
            ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest(
                    passwordReset.getFirst("reset_token"),
                    passwordReset.getFirst("new_password"),
                    passwordReset.getFirst("confirm_password")
            );
            CustomResponse response = resetService.resetPassword(changePasswordRequest);

            if (response.getError() == null && response.getData() != null) {
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.setLocation(URI.create(response.getData().toString()));

                ResponseEntity<Object> responseResponseEntity = ResponseEntity.status(301).headers(httpHeaders).body(response);
                log.info("Response {} ", responseResponseEntity);
                return responseResponseEntity;
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
        return ResponseEntity.badRequest().body(CustomResponse.builder().error(UnsuccessfulResponse.invalid_request)
                .errorDescription("Null password not allowed"));
    }
}
