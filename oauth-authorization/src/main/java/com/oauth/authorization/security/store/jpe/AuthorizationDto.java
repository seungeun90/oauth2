package com.oauth.authorization.security.store.jpe;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter
@NoArgsConstructor
public class AuthorizationDto {
    private AuthorizationJpe authorizationJpe;
    private AuthorizationCodeJpe authorizationCodeJpe;
    private AccessTokenJpe accessTokenJpe;
    private RefreshTokenJpe refreshTokenJpe;
    private OidcIdTokenJpe oidcIdTokenJpe;

}
