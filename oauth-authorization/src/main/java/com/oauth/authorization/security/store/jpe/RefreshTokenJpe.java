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
@Table(name="REFRESH_TOKEN")
public class RefreshTokenJpe {

    @Id
    @Column(name="ID")
    private String id;

    @Column(name="REFRESH_TOKEN_VALUE",length = 4000)
    private String refreshTokenValue;

    @Column(name="REFRESH_TOKEN_ISSUED_AT")
    private Instant refreshTokenIssuedAt;

    @Column(name="REFRESH_TOKEN_EXPRIES_AT")
    private Instant refreshTokenExpiresAt;

    @Column(name="REFRESH_TOKEN_METADATA",length = 2000)
    private String refreshTokenMetadata;

}
