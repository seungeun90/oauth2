package com.oauth.authorization.security.store.jpe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter @Setter
@NoArgsConstructor
@Entity
@Table(name="ACCESS_TOKEN")
public class AccessTokenJpe {

    @Id
    @Column(name="ID")
    private String id;

    @Column(name="ACCESS_TOKEN_VALUE",length = 4000)
    private String accessTokenValue;

    @Column(name="ACCESS_TOKEN_ISSUE_AT")
    private Instant accessTokenIssuedAt;

    @Column(name="ACCESS_TOKEN_EXPIRES_AT")
    private Instant accessTokenExpiresAt;

    @Column(name="ACEESS_TOKEN_METADATA",length = 2000)
    private String accessTokenMetadata;

    @Column(name="ACEESS_TOKEN_TYPE")
    private String accessTokenType;

    @Column(name="ACCESS_TOKEN_SCOPES",length = 1000)
    private String accessTokenScopes;

}
