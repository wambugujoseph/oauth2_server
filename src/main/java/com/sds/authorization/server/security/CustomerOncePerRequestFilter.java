package com.sds.authorization.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on May 25, 2024.
 * Time 4:28 PM
 */

@Configuration
public class CustomerOncePerRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION)).orElse("NONE");

        if (authHeader.startsWith("Bearer")){

        }

        filterChain.doFilter(request, response);
    }
}
