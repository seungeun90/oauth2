package com.oauth.authorization.security.store;

import com.oauth.authorization.domain.Account;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UserStore {

    List<Account> userDatabase = new ArrayList<>();

    public void save(Account account){
        userDatabase.add(account);
    }

    public Account findById(String id){
        for (Account acc : userDatabase) {
            if(acc.getId().equals(id)) return acc;
        }
        return null;
    }

    public Account findByEmail(String email){
        for (Account acc : userDatabase) {
            if(acc.getEmail().equals(email)) return acc;
        }
        return null;
    }
}
