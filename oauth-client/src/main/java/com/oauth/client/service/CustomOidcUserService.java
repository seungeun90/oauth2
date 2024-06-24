package com.oauth.client.service;

import com.oauth.client.domain.ProviderUser;
import com.oauth.client.repository.UserRepository;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
public class CustomOidcUserService extends AbstractOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = new OidcUserService();

    public CustomOidcUserService(UserService userService, UserRepository userRepository) {
        super(userService, userRepository);
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();

        OidcUser oidcUser = oidcUserService.loadUser(userRequest);

        ProviderUser providerUser = super.getOAuthUser(clientRegistration,oidcUser);
        super.register(providerUser, userRequest);

        return oidcUser;
    }
}
