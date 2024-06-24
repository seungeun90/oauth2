package com.oauth.authorization.domain;


import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;
import java.util.UUID;

@Getter
@AllArgsConstructor
public class OauthClient {

    private String clientName;
    private String clientId;
    private String clientSecret;
    private Set<String> scopes;
    private String redirectUris;


    public OauthClient(String clientName,
                       String redirectUris,
                       Set<String> scopes){
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.scopes = scopes;
    }
    public void createClientInfo(){
        this.clientId = issueUuid();
        this.clientSecret = issueUuid();
    }

    private String issueUuid() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
