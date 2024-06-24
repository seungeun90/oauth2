package com.oauth.client.service;

import com.oauth.client.domain.KakaoUser;
import com.oauth.client.domain.SampleUser;
import com.oauth.client.domain.ProviderUser;
import com.oauth.client.domain.User;
import com.oauth.client.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public abstract class AbstractOAuth2UserService {
    private final UserService userService;
    private final UserRepository userRepository;

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest){
        User user = userRepository.findByUsername(providerUser.getId());
         if(user == null){
            ClientRegistration clientRegistration = userRequest.getClientRegistration();
            userService.register(clientRegistration.getRegistrationId(), providerUser);
        } else {
            log.info("Already registered User ---- {}", user.getId());
        }
    }

    public ProviderUser getOAuthUser(ClientRegistration clientRegistration, OAuth2User oAuth2User){
        String registrationId = clientRegistration.getRegistrationId();
        if(registrationId.equals("kakao")){
            return new KakaoUser(oAuth2User,clientRegistration);
        }
        else if(registrationId.equals("sample")){
            return new SampleUser(oAuth2User,clientRegistration);
        }
        return null;
    }
}
