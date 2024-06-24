package com.oauth.client.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

@Getter
@AllArgsConstructor
public abstract class OAuth2ProviderUser implements ProviderUser {
    private Map<String, Object> attributes;
    private OAuth2User oAuth2User;
    private ClientRegistration clientRegistration;

    public OAuth2ProviderUser(OAuth2User oAuth2User, ClientRegistration clientRegistration){
        this.attributes = oAuth2User.getAttributes();
        this.oAuth2User = oAuth2User;
        this.clientRegistration = clientRegistration;
    }

}
