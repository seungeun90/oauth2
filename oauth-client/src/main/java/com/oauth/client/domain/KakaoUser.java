package com.oauth.client.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.List;
import java.util.Map;

public class KakaoUser extends OAuth2ProviderUser{

    public KakaoUser(OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(oAuth2User, clientRegistration);
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getEmail() {
        return (String) this.getAttributes().get("account_email");
    }

    @Override
    public String getUsername() {
        return (String) this.getAttributes().get("name");
    }

    @Override
    public String getMobile() {
        return (String) this.getAttributes().get("phone_number");
    }

    @Override
    public String getPassword() {
        return (String) this.getAttributes().get("password");
    }

    @Override
    public String getId() {
        return String.valueOf(this.getAttributes().get("id"));
    }

    @Override
    public List<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getCI() {
        return (String) this.getAttributes().get("account_ci");
    }

    @Override
    public String getBirthDay() {
        return
                (String) this.getAttributes().get("birthyear") +
                        "."+
                        (String) this.getAttributes().get("birthday");
    }

    @Override
    public String getGender() {
        return (String) this.getAttributes().get("gender");
    }

    public Map<String, Object> getAttributes() {
        return super.getAttributes();
    }
}

