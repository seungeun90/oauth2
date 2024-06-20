package com.oauth.client.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.List;
import java.util.Map;

public class NaverUser extends OAuth2ProviderUser {

    public NaverUser(OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(oAuth2User, clientRegistration);
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getPassword() {
        return (String) this.getAttributes().get("password");
    }

    @Override
    public String getId() {
        return (String) this.getAttributes().get("id");
    }

    @Override
    public List<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getEmail() {
        return (String) this.getAttributes().get("email");
    }

    @Override
    public String getUsername() {
        return (String) this.getAttributes().get("name");
    }

    @Override
    public String getMobile() {
        return (String) this.getAttributes().get("mobile");
    }

    @Override
    public String getCI() {
        return null;
    }

    @Override
    public String getBirthDay() {
        return null;
    }

    @Override
    public String getGender() {
        return null;
    }

    public Map<String, Object> getAttributes() {
        return this.getAttributes();
    }
}

