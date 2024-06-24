package com.oauth.client.repository;

import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaAuthorizedClientRepository extends JpaRepository<AuthorizedClientJpe, ClientPK> {
    AuthorizedClientJpe findByClientPkClientRegistrationIdAndClientPkPrincipalName(String clientRegistrationId, String principalName);
    void deleteByClientPkClientRegistrationIdAndClientPkPrincipalName(String clientRegistrationId, String principalName);
}
