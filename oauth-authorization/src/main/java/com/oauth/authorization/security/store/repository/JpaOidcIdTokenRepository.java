package com.oauth.authorization.security.store.repository;

import com.oauth.authorization.security.store.jpe.OidcIdTokenJpe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaOidcIdTokenRepository extends JpaRepository<OidcIdTokenJpe, String> {
    Optional<OidcIdTokenJpe> findByOidcIdTokenValue(String oidcIdToken);
}
