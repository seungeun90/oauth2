package com.oauth.authorization.security.service;


import com.oauth.authorization.domain.Account;
import com.oauth.authorization.security.store.UserStore;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserDetailsLogic implements UserDetailsService {
	private final UserStore userRepository;
	@Override
	public UserDetails loadUserByUsername(String username) {
		Account account = userRepository.findByEmail(username);
		return new User(username, account.getPassword(),
				true, true,
				true, true,
				Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
	}

}