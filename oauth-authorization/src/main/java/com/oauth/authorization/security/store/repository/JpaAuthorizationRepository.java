package com.oauth.authorization.security.store.repository;

import com.oauth.authorization.security.store.jpe.AuthorizationJpe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaAuthorizationRepository extends JpaRepository<AuthorizationJpe, String> {
    Optional<AuthorizationJpe> findByState(String state);
}
