package com.oauth.authorization.controller.dto;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;


@Getter @Setter
@NoArgsConstructor(access = AccessLevel.PUBLIC)
public class RegisteredClientRequest {
	private String clientName;
	private String redirectUris;
	private Set<String> scopes;
}