package com.oauth.client.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Getter
@NoArgsConstructor
public class User {
    private String registrationId;
    private String id;
    private String username;
    private String password;
    private String provider;
    private String email;
    private List<? extends GrantedAuthority> authorities;

    @Builder
    public User(
        String registrationId,
        String id,
        String username,
        String password,
        String provider,
        String email,
        List<? extends GrantedAuthority> authorities
    ){
        this.registrationId = registrationId;
        this.id = id;
        this.username = username;
        this.password = password;
        this.provider = provider;
        this.email = email;
        this.authorities = authorities;
    }
}
