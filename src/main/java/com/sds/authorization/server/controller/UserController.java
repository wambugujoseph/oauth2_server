package com.sds.authorization.server.controller;

import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.service.UserService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 12:03 AM
 */


@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping(value = "/api/v1/register/user", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createUser(@RequestBody UserCreatedDto userCreatedDto) {
        CustomResponse customResponse = userService.createUser(userCreatedDto);
        return ResponseEntity.status(Integer.parseInt(customResponse.getResponseCode())).body(customResponse);

    }

    @PutMapping (value = "/api/v1/update/user", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> updateUser(@RequestBody UserCreatedDto userCreatedDto) {
        CustomResponse customResponse = userService.updateUser(userCreatedDto);
        return ResponseEntity.status(Integer.parseInt(customResponse.getResponseCode())).body(customResponse);

    }
}
