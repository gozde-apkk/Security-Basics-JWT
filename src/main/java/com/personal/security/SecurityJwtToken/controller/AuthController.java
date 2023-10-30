package com.personal.security.SecurityJwtToken.controller;

import com.personal.security.SecurityJwtToken.dto.LoginRequest;
import com.personal.security.SecurityJwtToken.dto.LoginResponse;
import com.personal.security.SecurityJwtToken.dto.RegistrationUser;
import com.personal.security.SecurityJwtToken.service.AuthenticationService;
import com.personal.security.SecurityJwtToken.user.ApplicationUser;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthenticationService authenticationService;

    @Autowired
    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ApplicationUser register(@RequestBody RegistrationUser user){
        return authenticationService.register(user.getFirstName(), user.getLastName(),
                user.getEmail(), user.getPassword());
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest){
        return authenticationService.login(loginRequest.getEmail(), loginRequest.getPassword());
    }


}