package com.example.springsecurityauthorization.domain.dto;

import com.example.springsecurityauthorization.configuration.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserLoginRequest {

    private String userName;
    private String password;
    private UserRole userRole;

}
