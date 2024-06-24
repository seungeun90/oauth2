package com.oauth.authorization.security.service;


import com.oauth.authorization.domain.OauthClient;

public interface RegisteredClientService {
    void save(OauthClient client);
}
