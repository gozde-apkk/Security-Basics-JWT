package com.personal.security.SecurityJwtToken.dto;

import com.personal.security.SecurityJwtToken.user.ApplicationUser;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {

    private ApplicationUser user;

    private String jwt;
}
