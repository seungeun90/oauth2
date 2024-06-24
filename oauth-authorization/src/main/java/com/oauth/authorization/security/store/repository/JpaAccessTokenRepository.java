package com.oauth.authorization.security.store.repository;

import com.oauth.authorization.security.store.jpe.AccessTokenJpe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaAccessTokenRepository extends JpaRepository<AccessTokenJpe, String> {
    Optional<AccessTokenJpe> findByAccessTokenValue(String accessToken);
}
