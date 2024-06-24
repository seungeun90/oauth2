package com.oauth.authorization.security.provider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final UserDetailsService userDetailsLogic;

	@Override
	public Authentication authenticate(Authentication authentication) {
		String username = String.valueOf(authentication.getPrincipal());
		String password = String.valueOf(authentication.getCredentials());

		UserDetails userDetails = userDetailsLogic.loadUserByUsername(username);

		validatePassword(password, userDetails.getPassword());

		return new UsernamePasswordAuthenticationToken(username, authentication.getCredentials(),
				Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
	}
	private void validatePassword(final String rawPassword, final String encodedPassword){
		String decrypted = "sample@@"; //decrypt
		if( !rawPassword.equals(decrypted) ) {
			throw new RuntimeException("invalid password");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}