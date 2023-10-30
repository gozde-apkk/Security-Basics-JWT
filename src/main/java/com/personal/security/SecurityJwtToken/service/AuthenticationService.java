package com.personal.security.SecurityJwtToken.service;

import com.personal.security.SecurityJwtToken.dto.LoginResponse;
import com.personal.security.SecurityJwtToken.repository.RoleRepository;
import com.personal.security.SecurityJwtToken.repository.UserRepository;
import com.personal.security.SecurityJwtToken.user.ApplicationUser;


import com.personal.security.SecurityJwtToken.user.Role;
import org.springframework.beans.factory.annotation.Autowired;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthenticationService {

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;


    private AuthenticationManager authenticationManager;
    private TokenService tokenService;


    public AuthenticationService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder,
                                 AuthenticationManager authenticationManager, TokenService tokenService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    public ApplicationUser register(String firstName, String lastName,
                                    String email, String password){
        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER").get();
        Set<Role> authorities = new HashSet<>();
        authorities.add(userRole);

        ApplicationUser user = new ApplicationUser();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmail(email);
        user.setPassword(encodedPassword);
        user.setAuthorities(authorities);
        return userRepository.save(user);
    }


    public LoginResponse login(String email, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password));
            String token = tokenService.generateKey(auth);
            return new LoginResponse(userRepository.findUserByEmail(email).get(), token);
        } catch (AuthenticationException ex) {
            return new LoginResponse(null, "");
        }
    }
}
