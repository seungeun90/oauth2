package com.oauth.client.config;

import com.oauth.client.config.handler.CustomAuthenticationFailureHandler;
import com.oauth.client.config.handler.CustomAuthenticationSuccessHandler;
import com.oauth.client.service.CustomOAuthUserService;
import com.oauth.client.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig {
    private final CustomAuthenticationSuccessHandler successHandler;
    private final CustomOAuthUserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;
    @Bean
    @Order(1)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
               .requestMatchers("/logout","/", "/login","/error**").permitAll()
                .anyRequest().authenticated()
                );

        http.oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfoEndpointConfig ->
                                userInfoEndpointConfig.userService(customOAuth2UserService)
                                .oidcUserService(customOidcUserService))
                        .successHandler(successHandler)
                        .failureHandler(new CustomAuthenticationFailureHandler())
                )
                .csrf(AbstractHttpConfigurer::disable);

        http.logout(httpSecurityLogoutConfigurer ->
                httpSecurityLogoutConfigurer.logoutSuccessUrl("/"));

        return http.build();
    }

}
