package com.oauth.authorization.security.store;

import com.oauth.authorization.security.store.jpe.OidcIdTokenJpe;
import com.oauth.authorization.security.store.repository.JpaOidcIdTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JpaOidcIdTokenStore {
    private final JpaOidcIdTokenRepository oidcIdTokenRepository;

    public OidcIdTokenJpe retrieveOidcIdTokenById(String id){
        Optional<OidcIdTokenJpe> token = oidcIdTokenRepository.findById(id);
        return token.isPresent() ? token.get() : null;
    }

    public OidcIdTokenJpe retrieveOidcIdTokenByValue(String token){
        return oidcIdTokenRepository.findByOidcIdTokenValue(token).get();
    }

    public void save(OidcIdTokenJpe jpe) {
        oidcIdTokenRepository.save(jpe);
    }

    public void removeOidcIdToken(String id){
        oidcIdTokenRepository.deleteById(id);
    }
}
