package com.sds.authorization.server.controller;

import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.service.UserService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 12:03 AM
 */


@RestController
public class UserController {

    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(value = "/api/v1/register/user", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE, method = RequestMethod.POST)
    public ResponseEntity<?> createUser(@RequestBody UserCreatedDto userCreatedDto){
        userService.createUser(userCreatedDto);
        return ResponseEntity.ok().build();

    }
}
