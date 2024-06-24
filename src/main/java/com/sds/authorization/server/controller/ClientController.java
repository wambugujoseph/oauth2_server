package com.sds.authorization.server.controller;

import com.sds.authorization.server.dto.ClientCreateDto;
import com.sds.authorization.server.dto.UserCreatedDto;
import com.sds.authorization.server.model.OauthClientDetails;
import com.sds.authorization.server.service.ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * @author Joseph Kibe
 * Created on June 13, 2024.
 * Time 8:15 AM
 */

@RestController
public class ClientController {

    private final ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    @PostMapping(value = "/api/v1/register/client", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createUser(@RequestBody ClientCreateDto clientCreateDto){
        OauthClientDetails clientDetails = clientService.createOauthClientDetails(clientCreateDto);
        return ResponseEntity.ok(clientDetails);
    }
}
