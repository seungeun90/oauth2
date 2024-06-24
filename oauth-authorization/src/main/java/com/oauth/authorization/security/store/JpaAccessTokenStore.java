package com.oauth.authorization.security.store;

import com.oauth.authorization.security.store.jpe.AccessTokenJpe;
import com.oauth.authorization.security.store.repository.JpaAccessTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
@RequiredArgsConstructor
public class JpaAccessTokenStore {

    private final JpaAccessTokenRepository accessTokenRepository;

    public AccessTokenJpe retrieveAccessTokenById(String id){
        Optional<AccessTokenJpe> token = (Optional<AccessTokenJpe>) accessTokenRepository.findById(id);
        return token.isPresent()? token.get() : null;
    }
    public AccessTokenJpe retrieveAccessTokenByValue(String token){
        return accessTokenRepository.findByAccessTokenValue(token).get();
    }
    public void save(AccessTokenJpe jpe) {
        accessTokenRepository.save(jpe);
    }

    public void removeAccessToken(String id){
        accessTokenRepository.deleteById(id);
    }

}
