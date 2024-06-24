package com.oauth.authorization.security.store.jpe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter
@NoArgsConstructor
@Entity
@Table(name="AUTHORIZATION")
public class AuthorizationJpe {

    @Id
    @Column(name="ID")
    private String id;

    @Column(name="REGISTERED_CLIENT_ID")
    private String registeredClientId;

    @Column(name="PRINCIPAL_NAME")
    private String principalName;

    @Column(name="AUTHORIZATION_GRANT_TYPE")
    private String authorizationGrantType;

    @Column(name="AUTHORIZATION_SCOPES",length = 1000)
    private String authorizedScopes;

    @Column(name="ATTRIBUTES",length = 4000)
    private String attributes;

    @Column(name="STATE",length = 500)
    private String state;


    @Builder
    public AuthorizationJpe(
        String registeredClientId,
        String principalName,
        String authorizationGrantType,
        String authorizedScopes,
        String attributes,
        String state
    ){
        this.registeredClientId = registeredClientId;
        this.principalName = principalName;
        this.authorizationGrantType = authorizationGrantType;
        this.authorizedScopes = authorizedScopes;
        this.attributes = attributes;
        this.state = state;
    }

}
