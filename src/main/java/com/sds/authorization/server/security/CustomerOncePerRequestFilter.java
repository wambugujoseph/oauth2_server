package com.sds.authorization.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.EncryptedJWT;
import com.sds.authorization.server.model.CustomResponse;
import com.sds.authorization.server.model.Role;
import com.sds.authorization.server.model.UnsuccessfulResponse;
import com.sds.authorization.server.model.User;
import com.sds.authorization.server.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * @author Joseph Kibe
 * Created on May 25, 2025.
 * Time 4:28 PM
 */

@Configuration
@Slf4j
public class CustomerOncePerRequestFilter extends OncePerRequestFilter {

    public final JwtTokenUtil jwtTokenUti;
    private final UserService userService;

    public CustomerOncePerRequestFilter(JwtTokenUtil jwtTokenUti, UserService userService) {
        this.jwtTokenUti = jwtTokenUti;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION)).orElse("NONE");

        if (authHeader.startsWith("Bearer")) {
            String token = authHeader.replace("Bearer ", "").trim();
            log.info("Token: {}", token);
            Object object = jwtTokenUti.verifyToken(token);

            if (object instanceof EncryptedJWT jwt) {

                try {
                    String email = jwt.getJWTClaimsSet().getStringClaim("email");
                    User user = userService.getActiveUserByEmail(email);
                    List<GrantedAuthority> authorities = new ArrayList<>();
                    Role role = user.getRole();

                    if (role != null) {
                        role.getPermissions().forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getPermissionName())));
                    }
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            user, user.getPassword(), authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                    markResponseUnauthorised(response);
                }
            }else {
                markResponseUnauthorised(response);
            }
        }
        filterChain.doFilter(request, response);
    }

    public void markResponseUnauthorised(HttpServletResponse response) throws IOException {
        ObjectMapper objMp = new ObjectMapper();
        String error = objMp.writeValueAsString(CustomResponse.builder()
                .responseCode("UnAuthorised Request")
                .error(UnsuccessfulResponse.unauthorized_client)
                .build());

        try {//
            response.reset();
        } catch (Exception ignored) {}
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
        response.setHeader("Access-Control-Allow-Headers", "*");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setContentLength(error.length());
        response.getWriter().write(error);

        SecurityContextHolder.clearContext();
    }
}
