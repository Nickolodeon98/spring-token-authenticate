package com.example.springsecurityauthorization.utils;

import com.example.springsecurityauthorization.configuration.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    public static String createToken(String username, UserRole userRole) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("role", userRole.name());
        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + (1000L * 60 * 60)))
                .signWith(SignatureAlgorithm.HS256, "secretKey")
                .compact();
    }
}
