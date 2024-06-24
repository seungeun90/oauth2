package com.oauth.authorization.security.store;

import com.oauth.authorization.security.store.jpe.AuthorizationCodeJpe;
import com.oauth.authorization.security.store.repository.JpaAuthorizationCodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JpaAuthorizationCodeStore {

    private final JpaAuthorizationCodeRepository codeRepository;

    public AuthorizationCodeJpe retrieveAuthorizationCodeById(String id){
        return codeRepository.findById(id).get();
    }

    public AuthorizationCodeJpe retrieveAuthorizationCodeByValue(String code){
        Optional<AuthorizationCodeJpe> jpe = codeRepository.findByAuthorizationCodeValue(code);
        return jpe.isPresent()? jpe.get() : null;
    }


    public void save(AuthorizationCodeJpe jpe) {
        codeRepository.save(jpe);
    }

    public void removeAuthorizationCode(String id){
        codeRepository.deleteById(id);
    }

}
