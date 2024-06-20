package com.oauth.client.service;

import com.oauth.client.domain.ProviderUser;
import com.oauth.client.domain.User;
import com.oauth.client.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public void register(String registrationId, ProviderUser oAuthUser) {
        User user = User.builder().registrationId(registrationId)
                .id(oAuthUser.getId())
                .username(oAuthUser.getUsername())
                .password(oAuthUser.getPassword())
                .authorities(oAuthUser.getAuthorities())
                .provider(oAuthUser.getProvider())
                .email(oAuthUser.getEmail())
                .build();

        userRepository.register(user);
    }
}
