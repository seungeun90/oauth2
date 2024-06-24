package com.oauth.client.domain;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;

public interface ProviderUser {
    Map<String, Object> getAttributes();
    String getProvider();
    String getEmail();
    String getUsername();
    String getMobile();
    String getPassword();
    String getId();
    List<? extends GrantedAuthority> getAuthorities();
    String getCI();

    String getBirthDay();
    String getGender();
}
