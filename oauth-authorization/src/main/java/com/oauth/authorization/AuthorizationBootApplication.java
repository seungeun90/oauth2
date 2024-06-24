package com.oauth.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class AuthorizationBootApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationBootApplication.class, args);
    }
}
