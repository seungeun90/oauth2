package com.oauth.authorization.service.logic;

import com.oauth.authorization.domain.OauthClient;
import com.oauth.authorization.service.service.OAuth2RegisteredClientService;
import com.oauth.authorization.security.service.RegisteredClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OAuth2RegisteredClientLogic implements OAuth2RegisteredClientService {

    private final RegisteredClientService clientService;

    @Override
    public OauthClient save(OauthClient client) {
        client.createClientInfo();
        clientService.save(client);
        return client;
    }
}
