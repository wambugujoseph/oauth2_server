package com.sds.authorization.server.security;

import com.sds.authorization.server.configuration.AppProps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * @author Joseph Kibe
 * Created on March 17, 2023.
 * Time 5:21 PM
 *
 * <p>
 * The class provides configurations on how different API endpoint will be Authorized And Authenticated
 * <b>: Configuring SecurityFilterChain</b>
 * <p> Provide Description on how each end point should be handled in term of security</p>
 * @EnableMethodSecurity Class level tag will allow method level access control Based on Role (RBAC)
 * This helps to determine what user can or cannot access (Authorization) having provided the right credential
 * (Authentication)
 */

@Configuration
@EnableMethodSecurity(jsr250Enabled = true)
@EnableWebMvc
@EnableWebSecurity
//JSR250 to allow Use of AllowedRole Annotation instead of Spring PreAuthorization
public class WebSecurityConfiguration {

    @Autowired
    @Qualifier("customAuthenticationEntryPoint")
    AuthenticationEntryPoint authEntryPoint;
    @Autowired
    AppProps config;
    @Autowired
    private CustomerOncePerRequestFilter perRequestFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /*--------------------------------------------------------------------------------------------------------------
        To Prevent Access Of the application using JSESSIONID Cookie on live it should be disabled
        JSESSIONID cookie is important only when accessing application over the browser which is only applicable
        when accessing Swagger documentation since it is secured. On live environment the Swagger is expected to be
         disabled, thus no session generation is required.
        Controlled Over Environment variable API_ENV_LIVE
         ---------------------------------------------------------------------------------------------------------------
         */

        SessionCreationPolicy sessionCreationPolicy = getSessionCreationPolicy();

        http.csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .requestMatchers("/login", "/login/**", "/logout", "/resources/**",
                                        "/api/v1/tokeninfo", "/api/v1/oauth/token", "/api/v1/register/user")
                                .permitAll()
                                .anyRequest()
                                .authenticated())
                .httpBasic(basic -> basic.authenticationEntryPoint(authEntryPoint))
                .exceptionHandling(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(sessionCreationPolicy))
                .formLogin(httpSecurityFormLoginConfigurer ->
                        httpSecurityFormLoginConfigurer
                                .loginPage("/login")
                                .defaultSuccessUrl("/api/v1/doc/", true)
                                                               );

        http.addFilterBefore(perRequestFilter,
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    /**
     * If removed To Error <p>No thread-bound request found: Are you referring to request attributes outside of an
     * actual web request, or processing a request outside of the originally receiving thread? If you are actually
     * operating within a web request and still receive this message, your code is probably running outside of
     * DispatcherServlet: In this case, use
     * RequestContextListener or RequestContextFilter to expose the current request.</p>
     *
     * @return RequestContextListener
     */
   @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }


    private SessionCreationPolicy getSessionCreationPolicy() {
        SessionCreationPolicy sessionCreationPolicy;

        if (config.isAppLive()) {
            sessionCreationPolicy = SessionCreationPolicy.STATELESS; // Block Session creation
        } else {
            sessionCreationPolicy = SessionCreationPolicy.IF_REQUIRED; // Allow Session creation
        }

        return sessionCreationPolicy;
    }

}
