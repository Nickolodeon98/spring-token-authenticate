package com.example.springsecurityauthorization.utils;

import com.example.springsecurityauthorization.configuration.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    public static String getUserName(String token, String secretKey) {
        return extractClaims(token, secretKey).getSubject();
    }

    public static String getUserRole(String token, String secretKey) {
        return extractClaims(token, secretKey).get("role", String.class);
    }

    public static String createToken(String username, UserRole userRole, String secretKey) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("role", userRole.name());
        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + (1000L * 60 * 60)))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public static Claims extractClaims(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    public static boolean isExpired(String token, String secretKey) {
        return extractClaims(token, secretKey).getExpiration().before(new Date());
    }

    public static Authentication getAuthentication(String userName, String userRole) {
        // 여기서 setDetails 를 왜 해야하는지?
        return new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority(userRole)));
    }
}
