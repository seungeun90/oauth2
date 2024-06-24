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
@Table(name="OIDC_TOKEN")
public class OidcIdTokenJpe {

    @Id
    @Column(name="ID")
    private String id;

    @Column(name="OIDC_TOKEN_VALUE",length = 4000)
    private String oidcIdTokenValue;

    @Column(name="OIDC_TOKEN_ISSUED_AT")
    private Instant oidcIdTokenIssuedAt;

    @Column(name="OIDC_TOKEN_EXPRIES_AT")
    private Instant oidcIdTokenExpiresAt;

    @Column(name="OIDC_TOKEN_METADATA",length = 2000)
    private String oidcIdTokenMetadata;

    @Column(name="OIDC_TOKEN_CLAIMS", length = 2000)
    private String oidcIdTokenClaims;

}
