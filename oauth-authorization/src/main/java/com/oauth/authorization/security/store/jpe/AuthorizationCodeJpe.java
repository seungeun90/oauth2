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
@Table(name="AUTHORIZATION_CODE")
public class AuthorizationCodeJpe {

    @Id
    @Column(name="ID")
    private String id;

    @Column(name="AUTHORIZATION_CODE_VALUE",length = 4000)
    private String authorizationCodeValue;

    @Column(name="AUTHORIZATION_CODE_ISSUED_AT")
    private Instant authorizationCodeIssuedAt;

    @Column(name="AUTHORIZATION_CODE_EXPRIES_AT")
    private Instant authorizationCodeExpiresAt;

    @Column(name="AUTHORIZATION_CODE_METADATA")
    private String authorizationCodeMetadata;
}
