package com.example.springsecurityauthorization.configuration;

import com.example.springsecurityauthorization.service.UserService;
import com.example.springsecurityauthorization.utils.JwtTokenProvider;
import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserService userService;
//    @Value("${jwt.token.secret}")
    private final String secretKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = null;
        try {
            token = authorizationHeader.split(" ")[1];
        } catch (Exception e) {
            filterChain.doFilter(request, response);
            throw new RuntimeException(e);
        }

        if (JwtTokenProvider.isExpired(token, secretKey)) filterChain.doFilter(request, response);

        String userName = JwtTokenProvider.getUserName(token, secretKey);
        String userRole = JwtTokenProvider.getUserRole(token, secretKey);

        SecurityContextHolder.getContext().setAuthentication(JwtTokenProvider.getAuthentication(userName, userRole));
        filterChain.doFilter(request, response);
    }
}
