package com.oauth.authorization.security.store.repository;


import com.oauth.authorization.security.store.jpe.RegisteredClientJpe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaRegisteredClientRepository extends JpaRepository<RegisteredClientJpe, String> {
    Optional<RegisteredClientJpe> findByClientId(String clientId);

}
