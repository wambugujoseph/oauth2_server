package com.sds.authorization.server.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.HttpRetryException;

/**
 * @author Joseph Kibe
 * Created on December 09, 2023.
 * Time 12:35 PM
 */

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomGenericFilter extends GenericFilter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
        response.setHeader("Access-Control-Allow-Headers", "*");
        //servletResponse.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        }else if (request.getMethod() == null || request.getMethod().isEmpty()){
            throw new HttpRetryException("Unauthorized",HttpStatus.UNAUTHORIZED.value());
        }else {
            try {
                filterChain.doFilter(servletRequest, servletResponse);
            } catch (Exception e) {
                System.out.println("---------e"+e.getMessage());
            }
        }
    }
}
