package com.sds.authorization.server.security;

import com.nimbusds.jwt.EncryptedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hibernate.sql.exec.spi.StandardEntityInstanceResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
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

    public final JwtTokenUtil jwtTokenUti;

    public CustomerOncePerRequestFilter(JwtTokenUtil jwtTokenUti) {
        this.jwtTokenUti = jwtTokenUti;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION)).orElse("NONE");

        if (authHeader.startsWith("Bearer")){
            String token = authHeader.replace("Bearer", "").trim();

            Object object = jwtTokenUti.verifyToken(token);

            if (object instanceof EncryptedJWT jwt){
               //String email = jwt.getJWTClaimsSet().getStringClaim("email");

            }

        }

        filterChain.doFilter(request, response);
    }
}
