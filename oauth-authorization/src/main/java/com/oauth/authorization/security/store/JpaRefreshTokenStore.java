package com.oauth.authorization.security.store;

import com.oauth.authorization.security.store.jpe.RefreshTokenJpe;
import com.oauth.authorization.security.store.repository.JpaRefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JpaRefreshTokenStore {
    private final JpaRefreshTokenRepository refreshTokenRepository;

    public RefreshTokenJpe retrieveRefreshTokenById(String id){
        Optional<RefreshTokenJpe> token = refreshTokenRepository.findById(id);
        return token.isPresent() ? token.get() : null;
    }

    public RefreshTokenJpe retrieveRefreshTokenByValue(String token){
        return refreshTokenRepository.findByRefreshTokenValue(token).get();
    }

    public void save(RefreshTokenJpe jpe) {
        refreshTokenRepository.save(jpe);
    }

    public void removeRefreshToken(String id){
        refreshTokenRepository.deleteById(id);
    }
}
