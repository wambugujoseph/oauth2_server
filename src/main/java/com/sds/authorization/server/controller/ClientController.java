package com.sds.authorization.server.controller;


import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URI;

/**
 * @author joseph.kibe
 * Created On 10/12/2024 12:09
 **/

@Controller
public class ClientController {

    @PostMapping(value = "api/v1/client-resource/login")
    public ResponseEntity<?> login(@RequestParam(value = "redirect_url", required = false) String redirectUrl){
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(redirectUrl));

        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .headers(headers)
                .build();
    }

    @GetMapping(value = "api/v1/client-resource/login")
    public String loginPage(@RequestParam(value = "redirect_url", required = false) String redirectUrl){;
        return "/login";
    }
}
