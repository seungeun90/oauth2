package com.oauth.authorization.service.service;


import com.oauth.authorization.domain.OauthClient;

public interface OAuth2RegisteredClientService {

    OauthClient save(OauthClient client);
}
