package com.oauth.authorization.security.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oauth.authorization.security.store.*;
import com.oauth.authorization.security.store.jpe.*;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;


public class OAuth2AuthorizationLogic implements OAuth2AuthorizationService {
    private ObjectMapper objectMapper;
    private JpaAuthorizationStore authorizationStore;
    private JpaAccessTokenStore accessTokenStore;
    private JpaRefreshTokenStore refreshTokenStore;
    private JpaOidcIdTokenStore oidcIdTokenStore;
    private JpaAuthorizationCodeStore authorizationCodeStore;
    private RegisteredClientRepository registeredClientRepository;

    public OAuth2AuthorizationLogic(
            JpaAuthorizationStore authorizationStore
            ,JpaAccessTokenStore accessTokenStore
            ,JpaRefreshTokenStore refreshTokenStore
            ,JpaOidcIdTokenStore oidcIdTokenStore
            ,JpaAuthorizationCodeStore authorizationCodeStore
            ,RegisteredClientRepository registeredClientRepository
    ) {
        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = OAuth2AuthorizationLogic.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        this.objectMapper =  objectMapper;
        this.authorizationStore = authorizationStore;
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.refreshTokenStore = refreshTokenStore;
        this.oidcIdTokenStore = oidcIdTokenStore;
        this.registeredClientRepository = registeredClientRepository;
    }
    @Override
    public void save(OAuth2Authorization authorization) {
        /** authority save */
        AuthorizationJpe authorizationJpe = new AuthorizationJpe();
        authorizationJpe.setId(authorization.getId());
        authorizationJpe.setRegisteredClientId(authorization.getRegisteredClientId());
        authorizationJpe.setPrincipalName(authorization.getPrincipalName());
        authorizationJpe.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        authorizationJpe.setAuthorizedScopes(StringUtils.collectionToCommaDelimitedString(authorization.getAuthorizedScopes()));
        authorizationJpe.setAttributes(writeMapAsString(authorization.getAttributes()));
        authorizationJpe.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

        authorizationStore.save(authorizationJpe);

        /** authorization code save */
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);

        if (authorizationCode != null) {
            AuthorizationCodeJpe authorizationCodeJpe = new AuthorizationCodeJpe();
            authorizationCodeJpe.setId(authorization.getId());
            setTokenValues(
                    authorizationCode,
                    authorizationCodeJpe::setAuthorizationCodeValue,
                    authorizationCodeJpe::setAuthorizationCodeIssuedAt,
                    authorizationCodeJpe::setAuthorizationCodeExpiresAt,
                    authorizationCodeJpe::setAuthorizationCodeMetadata
            );
            authorizationCodeStore.save(authorizationCodeJpe);
        }


        /** access token save */
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            AccessTokenJpe accessTokenJpe = new AccessTokenJpe();
            accessTokenJpe.setId(authorization.getId());
            setTokenValues(
                    accessToken,
                    accessTokenJpe::setAccessTokenValue,
                    accessTokenJpe::setAccessTokenIssuedAt,
                    accessTokenJpe::setAccessTokenExpiresAt,
                    accessTokenJpe::setAccessTokenMetadata
            );
            if (accessToken != null && accessToken.getToken().getScopes() != null) {
                accessTokenJpe.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
            }
            accessTokenStore.save(accessTokenJpe);

        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            RefreshTokenJpe refreshTokenJpe = new RefreshTokenJpe();
            refreshTokenJpe.setId(authorization.getId());
            setTokenValues(
                    refreshToken,
                    refreshTokenJpe::setRefreshTokenValue,
                    refreshTokenJpe::setRefreshTokenIssuedAt,
                    refreshTokenJpe::setRefreshTokenExpiresAt,
                    refreshTokenJpe::setRefreshTokenMetadata
            );
            refreshTokenStore.save(refreshTokenJpe);
        }

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
                authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            OidcIdTokenJpe oidcTokenJpe = new OidcIdTokenJpe();
            oidcTokenJpe.setId(authorization.getId());
            setTokenValues(
                    oidcIdToken,
                    oidcTokenJpe::setOidcIdTokenValue,
                    oidcTokenJpe::setOidcIdTokenIssuedAt,
                    oidcTokenJpe::setOidcIdTokenExpiresAt,
                    oidcTokenJpe::setOidcIdTokenMetadata
            );
            oidcTokenJpe.setOidcIdTokenClaims(writeMapAsString(oidcIdToken.getClaims()));
            oidcIdTokenStore.save(oidcTokenJpe);
        }
    }


    private void setTokenValues(
            OAuth2Authorization.Token<?> token,
            Consumer<String> tokenValueConsumer,
            Consumer<Instant> issuedAtConsumer,
            Consumer<Instant> expiresAtConsumer,
            Consumer<String> metadataConsumer) {
        if (token != null) {
            OAuth2Token oAuth2Token = token.getToken();
            tokenValueConsumer.accept(oAuth2Token.getTokenValue());
            issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
            expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
            metadataConsumer.accept(writeMapAsString(token.getMetadata()));
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        authorizationStore.removeAuthorization(authorization.getId());
        authorizationCodeStore.removeAuthorizationCode(authorization.getId());
        accessTokenStore.removeAccessToken(authorization.getId());
        refreshTokenStore.removeRefreshToken(authorization.getId());
        oidcIdTokenStore.removeOidcIdToken(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        AuthorizationJpe authorizationJpe = authorizationStore.retrieveAuthorizationById(id);
        AuthorizationCodeJpe authorizationCodeJpe = authorizationCodeStore.retrieveAuthorizationCodeById(id);
        AccessTokenJpe accessTokenJpe = accessTokenStore.retrieveAccessTokenById(id);
        RefreshTokenJpe refreshTokenJpe = refreshTokenStore.retrieveRefreshTokenById(id);
        OidcIdTokenJpe oidcIdTokenJpe = oidcIdTokenStore.retrieveOidcIdTokenById(id);

        return buildOAuth2Authorization(authorizationJpe,
                authorizationCodeJpe,
                accessTokenJpe,
                refreshTokenJpe,
                oidcIdTokenJpe);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        AuthorizationDto authorizationDto = null;
        if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            authorizationDto = byState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            authorizationDto = byAuthorizationCode(token);

        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            authorizationDto = byAccessToken(token);

        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            authorizationDto = byRefreshToken(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            authorizationDto = byOidcIdToken(token);
        }

        if(tokenType == null) {
            AuthorizationDto authorizationDto1 = byState(token);
            AuthorizationDto authorizationDto2 = byAuthorizationCode(token);
            AuthorizationDto authorizationDto3 = byAccessToken(token);
            AuthorizationDto authorizationDto4 = byRefreshToken(token);
            AuthorizationDto authorizationDto5 = byOidcIdToken(token);

            if(authorizationDto1 != null){
                authorizationDto = authorizationDto1;
            }
            if(authorizationDto2 != null){
                authorizationDto = authorizationDto2;
            }
            if(authorizationDto3 != null){
                authorizationDto = authorizationDto3;
            }
            if(authorizationDto4 != null){
                authorizationDto = authorizationDto4;
            }
            if(authorizationDto5 != null){
                authorizationDto = authorizationDto5;
            }

        }
        return buildOAuth2Authorization(
                authorizationDto.getAuthorizationJpe(),
                authorizationDto.getAuthorizationCodeJpe(),
                authorizationDto.getAccessTokenJpe(),
                authorizationDto.getRefreshTokenJpe(),
                authorizationDto.getOidcIdTokenJpe()
                );
    }

    private AuthorizationDto byAuthorizationCode(String token){
        AuthorizationCodeJpe authorizationCodeJpe = this.authorizationCodeStore.retrieveAuthorizationCodeByValue(token);
        String id = authorizationCodeJpe.getId();

        AuthorizationDto authorizationDto = new AuthorizationDto();
        authorizationDto.setAuthorizationJpe( this.authorizationStore.retrieveAuthorizationById(id));
        authorizationDto.setAuthorizationCodeJpe(authorizationCodeJpe);
        authorizationDto.setAccessTokenJpe(this.accessTokenStore.retrieveAccessTokenById(id));
        authorizationDto.setRefreshTokenJpe(this.refreshTokenStore.retrieveRefreshTokenById(id));
        authorizationDto.setOidcIdTokenJpe(this.oidcIdTokenStore.retrieveOidcIdTokenById(id));

        return authorizationDto;
    }
    private AuthorizationDto byAccessToken(String token){
        AccessTokenJpe accessTokenJpe = this.accessTokenStore.retrieveAccessTokenByValue(token);
        String id = accessTokenJpe.getId();

        AuthorizationDto authorizationDto = new AuthorizationDto();
        authorizationDto.setAuthorizationJpe( this.authorizationStore.retrieveAuthorizationById(id));
        authorizationDto.setAuthorizationCodeJpe(this.authorizationCodeStore.retrieveAuthorizationCodeById(id));
        authorizationDto.setAccessTokenJpe(accessTokenJpe);
        authorizationDto.setRefreshTokenJpe(this.refreshTokenStore.retrieveRefreshTokenById(id));
        authorizationDto.setOidcIdTokenJpe(this.oidcIdTokenStore.retrieveOidcIdTokenById(id));

        return authorizationDto;
    }
    private AuthorizationDto byRefreshToken(String token){
        RefreshTokenJpe refreshTokenJpe = this.refreshTokenStore.retrieveRefreshTokenByValue(token);
        String id = refreshTokenJpe.getId();

        AuthorizationDto authorizationDto = new AuthorizationDto();
        authorizationDto.setAuthorizationJpe( this.authorizationStore.retrieveAuthorizationById(id));
        authorizationDto.setAuthorizationCodeJpe(this.authorizationCodeStore.retrieveAuthorizationCodeById(id));
        authorizationDto.setAccessTokenJpe(this.accessTokenStore.retrieveAccessTokenById(id));
        authorizationDto.setRefreshTokenJpe(refreshTokenJpe);
        authorizationDto.setOidcIdTokenJpe(this.oidcIdTokenStore.retrieveOidcIdTokenById(id));

        return authorizationDto;
    }
    private AuthorizationDto byOidcIdToken(String token){
        OidcIdTokenJpe oidcIdTokenJpe = (OidcIdTokenJpe) this.oidcIdTokenStore.retrieveOidcIdTokenByValue(token);
        String id = oidcIdTokenJpe.getId();

        AuthorizationDto authorizationDto = new AuthorizationDto();
        authorizationDto.setAuthorizationJpe( this.authorizationStore.retrieveAuthorizationById(id));
        authorizationDto.setAuthorizationCodeJpe(this.authorizationCodeStore.retrieveAuthorizationCodeById(id));
        authorizationDto.setAccessTokenJpe(this.accessTokenStore.retrieveAccessTokenById(id));
        authorizationDto.setRefreshTokenJpe(this.refreshTokenStore.retrieveRefreshTokenById(id));
        authorizationDto.setOidcIdTokenJpe(oidcIdTokenJpe);

        return authorizationDto;
    }
    private AuthorizationDto byState(String token){
        AuthorizationJpe authorizationJpe = this.authorizationStore.retrieveAuthorizationByState(token);
        String id = authorizationJpe.getId();

        AuthorizationDto authorizationDto = new AuthorizationDto();
        authorizationDto.setAuthorizationJpe(authorizationJpe);
        authorizationDto.setAuthorizationCodeJpe(this.authorizationCodeStore.retrieveAuthorizationCodeById(id));
        authorizationDto.setAccessTokenJpe(this.accessTokenStore.retrieveAccessTokenById(id));
        authorizationDto.setRefreshTokenJpe(this.refreshTokenStore.retrieveRefreshTokenById(id));
        authorizationDto.setOidcIdTokenJpe(this.oidcIdTokenStore.retrieveOidcIdTokenById(id));

        return authorizationDto;
    }

    private OAuth2Authorization buildOAuth2Authorization(AuthorizationJpe entity,
                                                         AuthorizationCodeJpe authorizationCodeJpe,
                                                         AccessTokenJpe accessTokenJpe,
                                                         RefreshTokenJpe refreshTokenJpe,
                                                         OidcIdTokenJpe oidcIdTokenJpe){
        RegisteredClient registeredClient = this.registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }

        OAuth2Authorization.Builder builder =
                OAuth2Authorization.withRegisteredClient(registeredClient)
                        .id(entity.getId())
                        .principalName(entity.getPrincipalName())
                        .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                        .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
                        .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));

        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        if (authorizationCodeJpe != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationCodeJpe.getAuthorizationCodeValue(),
                    authorizationCodeJpe.getAuthorizationCodeIssuedAt(),
                    authorizationCodeJpe.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(authorizationCodeJpe.getAuthorizationCodeMetadata())));
        }

        if (accessTokenJpe != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    accessTokenJpe.getAccessTokenValue(),
                    accessTokenJpe.getAccessTokenIssuedAt(),
                    accessTokenJpe.getAccessTokenExpiresAt(),
                    StringUtils.commaDelimitedListToSet(accessTokenJpe.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(accessTokenJpe.getAccessTokenMetadata())));
        }

        if (refreshTokenJpe != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    refreshTokenJpe.getRefreshTokenValue(),
                    refreshTokenJpe.getRefreshTokenIssuedAt(),
                    refreshTokenJpe.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(refreshTokenJpe.getRefreshTokenMetadata())));
        }

        if (oidcIdTokenJpe != null) {
            OidcIdToken oidcIdToken = new OidcIdToken(
                    oidcIdTokenJpe.getOidcIdTokenValue(),
                    oidcIdTokenJpe.getOidcIdTokenIssuedAt(),
                    oidcIdTokenJpe.getOidcIdTokenExpiresAt(),
                    parseMap(oidcIdTokenJpe.getOidcIdTokenClaims()));
            builder.token(oidcIdToken, metadata -> metadata.putAll(parseMap(oidcIdTokenJpe.getOidcIdTokenMetadata())));
        }

        return builder.build();
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
    private String writeMapAsString(Map<String, Object> metadata) {
        try {
            return this.objectMapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
    }
}
