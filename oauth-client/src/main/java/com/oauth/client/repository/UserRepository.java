package com.oauth.client.repository;

import com.oauth.client.domain.User;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

@Repository
public class UserRepository {
    private Map<String,Object> users = new HashMap<String, Object>();

    public User findByUsername(String username){
        if(users.containsKey(username)){
            return (User)users.get(username);
        }
        return null;
    }
    public void register(User user){
        if(users.containsKey(user.getId())){
            return;
        }
        users.put(user.getId(),user);
    }
}
