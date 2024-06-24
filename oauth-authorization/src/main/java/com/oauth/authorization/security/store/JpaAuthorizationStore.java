package com.oauth.authorization.security.store;

import com.oauth.authorization.security.store.jpe.AuthorizationJpe;
import com.oauth.authorization.security.store.repository.JpaAuthorizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class JpaAuthorizationStore {
    private final JpaAuthorizationRepository authorizationRepository;

    public AuthorizationJpe retrieveAuthorizationById(String id){
        return authorizationRepository.findById(id).get();
    }

    public AuthorizationJpe retrieveAuthorizationByState(String state){
        return authorizationRepository.findByState(state).get();
    }

    public void save(AuthorizationJpe jpe) {
        authorizationRepository.save(jpe);
    }

    public void removeAuthorization(String id){
        authorizationRepository.deleteById(id);
    }

}
