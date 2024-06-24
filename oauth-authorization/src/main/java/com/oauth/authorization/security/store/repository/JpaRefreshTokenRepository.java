package com.oauth.authorization.security.store.repository;

import com.oauth.authorization.security.store.jpe.RefreshTokenJpe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaRefreshTokenRepository extends JpaRepository<RefreshTokenJpe, String> {
    Optional<RefreshTokenJpe> findByRefreshTokenValue(String accessToken);
}
