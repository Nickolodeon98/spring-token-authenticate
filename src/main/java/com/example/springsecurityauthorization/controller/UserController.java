package com.example.springsecurityauthorization.controller;

import com.example.springsecurityauthorization.domain.dto.UserLoginRequest;
import com.example.springsecurityauthorization.utils.JwtTokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/authorization")
public class UserController {

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserLoginRequest userLoginRequest) {
        String token = JwtTokenProvider.createToken(userLoginRequest.getUserName(), userLoginRequest.getUserRole());
        return ResponseEntity.ok().body(token);
    }
}
