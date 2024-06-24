package com.oauth.authorization.security.store.repository;

import com.oauth.authorization.security.store.jpe.AuthorizationCodeJpe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaAuthorizationCodeRepository extends JpaRepository<AuthorizationCodeJpe, String> {
    Optional<AuthorizationCodeJpe> findByAuthorizationCodeValue(String authorizationCode);
}
