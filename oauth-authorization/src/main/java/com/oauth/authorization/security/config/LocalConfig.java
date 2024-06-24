package com.oauth.authorization.security.config;

import com.oauth.authorization.domain.Account;
import com.oauth.authorization.security.store.UserStore;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class LocalConfig {
    private final UserStore userRepository;
    private final RegisteredClientRepository registeredClientRepository;

    @PostConstruct
    public void start(){
        saveUser();
        saveRegisteredClient();
    }

    private void saveUser(){
        Account user1 = Account.builder()
                .id(1L)
                .email("sample@gmail.com")
                .password("sample@@")
                .name("sample_name")
                .mobile("1234-1234")
                .gender("F")
                .role("user")
                .build();
        userRepository.save(user1);
    }
    private void saveRegisteredClient(){
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("64652bfddf80477ca4bb17f75f4a51fc")
                .clientSecret("f78513497e894566a96c5af5d9f23b0d")
                .clientName("test-oauth2")
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(Instant.MAX)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:81/client/login/oauth2/code/")
                .scopes(scopes -> scopes.addAll(Arrays.asList("openid","board")))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(365)).build())
                .build();

        registeredClientRepository.save(registeredClient);
    }
}
