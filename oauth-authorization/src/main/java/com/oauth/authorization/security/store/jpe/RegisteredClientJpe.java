package com.oauth.authorization.security.store.jpe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;

@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="REGISTERED_CLIENT")
public class RegisteredClientJpe {
    @Id
    @Column(name="ID")
    private String id;

    @Column(name="CLIENT_ID")
    private String clientId;

    @Column(name="CLIENT_ID_ISSUED_AT")
    private Instant clientIdIssuedAt;

    @Column(name="CLIENT_SECRET")
    private String clientSecret;

    @Column(name="CLIENT_SECRET_EXPRIRES_AT")
    private Instant clientSecretExpiresAt;

    @Column(name="CLIENT_NAME")
    private String clientName;

    @Column(name="CLIENT_AUTHENTICATION_METHODS",length = 1000)
    private String clientAuthenticationMethods;

    @Column(name="AUTHORIZATION_GRANT_TYPES",length = 1000)
    private String authorizationGrantTypes;

    @Column(name="REDIRECT_URIS",length = 1000)
    private String redirectUris;

    @Column(name="POST_LOGOUT_REDIRECT_URIS",length = 1000)
    private String postLogoutRedirectUris;

    @Column(name="SCOPES",length = 1000)
    private String scopes;

    @Column(name="CLIENT_SETTING",length = 2000)
    private String clientSettings;

    @Column(name="TOKEN_SETTING",length = 2000)
    private String tokenSettings;

    @Builder
    public RegisteredClientJpe(
            String clientId,
            Instant clientIdIssuedAt,
            String clientSecret,
            Instant clientSecretExpiredAt,
            String clientName,
            String clientAuthenticationMethods,
            String authorizationGrantTypes,
            String redirectUris,
            String postLogoutRedirectUris,
            String scopes,
           String clientSettings,
            String tokenSettings
    ){
        this.clientId = clientId;
        this.clientIdIssuedAt = clientIdIssuedAt;
        this.clientSecret = clientSecret;
        this.clientSecretExpiresAt = clientSecretExpiredAt;
        this.clientName = clientName;
        this.clientAuthenticationMethods = clientAuthenticationMethods;
        this.authorizationGrantTypes = authorizationGrantTypes;
        this.redirectUris = redirectUris;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.scopes = scopes;
        this.clientSettings = clientSettings;
        this.tokenSettings = tokenSettings;
    }

}
