package com.oauth.client.service;


import com.oauth.client.domain.ProviderUser;
import com.oauth.client.repository.UserRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuthUserService extends AbstractOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();

    public CustomOAuthUserService(UserService userService, UserRepository userRepository) {
        super(userService, userRepository);
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();

        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

        ProviderUser oAuthUser = super.getOAuthUser(clientRegistration, oAuth2User);
        super.register(oAuthUser, userRequest);

        return oAuth2User;
    }
}
