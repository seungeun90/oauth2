package com.oauth.authorization.security.config;

import com.oauth.authorization.security.handler.CustomAuthenticationFailureHandler;
import com.oauth.authorization.security.handler.CustomAuthenticationSuccessHandler;
import com.oauth.authorization.security.service.OAuth2AuthorizationLogic;
import com.oauth.authorization.security.store.*;
import com.oauth.authorization.security.store.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 서버 security 설정을 관리한다.
 */
@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {
	private final JpaAuthorizationRepository jpaAuthorizationRepository;
	private final JpaAuthorizationCodeRepository jpaAuthorizationCodeRepository;
	private final JpaAccessTokenRepository jpaAccessTokenRepository;
	private final JpaRefreshTokenRepository jpaRefreshTokenRepository;
	private final JpaOidcIdTokenRepository jpaOidcIdTokenRepository;
	private final JpaRegisteredClientRepository jpaRegisteredClientRepository;

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
		RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

		authorizationServerConfigurer
				.authorizationEndpoint(authorizationEndpoint ->
								authorizationEndpoint
										.errorResponseHandler(new CustomAuthenticationFailureHandler())
   					             	.authorizationResponseHandler(new CustomAuthenticationSuccessHandler())
                )
			//	.oidc(Customizer.withDefaults())
				.oidc(oidc -> oidc.clientRegistrationEndpoint(clientResigtrationEndpoint -> {
					clientResigtrationEndpoint.authenticationProviders(CustomClientMetadataConfig.configureCustomClientMetadataConverters());
				}));

		http
				.authorizeHttpRequests(request -> request.requestMatchers(
								"/login"
						).permitAll()
						.anyRequest().authenticated()
				)
				.csrf(AbstractHttpConfigurer::disable)
				.securityMatcher(endpointsMatcher)
				.exceptionHandling(ex->
						ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
				)
				.with(authorizationServerConfigurer, Customizer.withDefaults())
		;
		http.oauth2ResourceServer(resourceServiceConfig -> resourceServiceConfig.jwt(Customizer.withDefaults()));
		return http.build();
	}


	@Bean
	@Order(2)
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		return http
				/* csrf */
				.csrf(AbstractHttpConfigurer::disable)
				/* 헤더 프레임옵션 사용하지 않음 */
				.headers(c-> c.frameOptions(f->f.disable()).disable())
				.authorizeHttpRequests(request -> request
						/* embedded-db와 인증관련 url만 허용 */
						.requestMatchers("/h2-console/**",
								"/oauth2/registration",
								"/oauth2/authorize",
								"/oauth2/token",
								"/login"
						).permitAll()
						/* 다른 url은 인증 후 사용 가능 */
						.anyRequest().authenticated()
				)
				.formLogin(formlogin-> formlogin
								.loginPage("/login")
								.usernameParameter("username")
				)
				.build();
	}

	@Bean
	public OAuth2AuthorizationService oAuth2AuthorizationService(){
		return new OAuth2AuthorizationLogic(
				new JpaAuthorizationStore(jpaAuthorizationRepository)
				,new JpaAccessTokenStore(jpaAccessTokenRepository)
				,new JpaRefreshTokenStore(jpaRefreshTokenRepository)
				,new JpaOidcIdTokenStore(jpaOidcIdTokenRepository)
				,new JpaAuthorizationCodeStore(jpaAuthorizationCodeRepository)
				,registeredClientRepository()
		);
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(){
		return new JpaRegisteredClientStore(jpaRegisteredClientRepository, passwordEncoder());
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
													   PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder);
		return new ProviderManager(authenticationProvider);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}



}
