/*
 * Copyright 2018 Ronny "Sephiroth" Perinke <sephiroth@sephiroth-j.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.sephirothj.spring.security.ltpa2;

import java.security.PublicKey;
import java.util.Optional;
import javax.crypto.SecretKey;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

/**
 * <p>
 * A convenient way to configure {@link Ltpa2Filter the pre-authentication filter}.</p>
 * <p>
 * How to use:</p>
 * <pre>
 * public class WebSecurityConfig extends WebSecurityConfigurerAdapter
 * {
 *
 * 	&#064;Override
 * 	protected void configure(HttpSecurity http) throws Exception
 * 	{
 * 		http
 * 			.authorizeRequests()
 * 				.antMatchers("/", "/home").permitAll()
 * 				.antMatchers("/hello").hasRole("DEVELOPERS")
 * 				.and()
 * 			.apply(new Ltpa2Configurer())
 * 				.sharedKey(sharedKey())
 * 				.signerKey(signerKey())
 * 			;
 *		http.userDetailsService(userDetailsService());
 * 	}
 * }
 * </pre>
 * <p>
 * <b>A {@link UserDetailsService} is required!</b> In case no instance is exposed, you have to provide one using {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder#userDetailsService(org.springframework.security.core.userdetails.UserDetailsService) AuthenticationManagerBuilder#userDetailsService}.</p>
 *
 * @author Sephiroth
 */
@Accessors(fluent = true)
public class Ltpa2Configurer extends AbstractHttpConfigurer<Ltpa2Configurer, HttpSecurity>
{
	/**
	 * <p>
	 * the name of the cookie expected to contain the LTPA2 token</p>
	 * <p>
	 * default: {@code "LtpaToken2"}</p>
	 */
	private String cookieName = "LtpaToken2";

	/**
	 * <p>
	 * the name of header expected to contain the LTPA2 token</p>
	 * <p>
	 * default: {@value HttpHeaders#AUTHORIZATION}</p>
	 */
	private String headerName = HttpHeaders.AUTHORIZATION;

	/**
	 * <p>
	 * the prefix in {@link #headername the header} preceding the LTPA2 token (may be empty)</p>
	 * <p>
	 * default: {@code cookieName + " "}</p>
	 *
	 * @see #cookieName
	 */
	@Setter
	@NonNull
	private String headerValueIdentifier = cookieName + " ";

	/**
	 * the public key from the identity provider that sends the LTPA2-tokens. required for signature validation.
	 */
	@Setter
	@NonNull
	private PublicKey signerKey;

	/**
	 * the shared secret key that is used to encrypt LTPA2 tokens
	 */
	@Setter
	@NonNull
	private SecretKey sharedKey;

	/**
	 * <p>
	 * allow expired tokens</p>
	 * <p>
	 * <b>Do not use in prodcution mode, only for testing!</b></p>
	 */
	@Setter
	private boolean allowExpiredToken = false;

	/**
	 * allows to change the default behaviour when an authentication failure occurs.
	 * <p>
	 * The default is to respond with 403 status code</p>
	 */
	@Setter
	@Nullable
	private AuthenticationFailureHandler authFailureHandler;

	@Override
	public void configure(HttpSecurity builder)
	{
		UserDetailsService userDetailsService = Optional.ofNullable(builder.getSharedObject(ApplicationContext.class))
			.map(ctx -> ctx.getBean(UserDetailsService.class))
			.orElseThrow(() -> new IllegalStateException("A UserDetailsService must be known in this context"));
		Ltpa2Filter ltpaFilter = new Ltpa2Filter();
		ltpaFilter.setUserDetailsService(userDetailsService);
		ltpaFilter.setCookieName(cookieName);
		ltpaFilter.setHeaderName(headerName);
		ltpaFilter.setHeaderValueIdentifier(headerValueIdentifier);
		ltpaFilter.setSharedKey(sharedKey);
		ltpaFilter.setSignerKey(signerKey);
		ltpaFilter.setAllowExpiredToken(allowExpiredToken);
		if (authFailureHandler != null) {
			ltpaFilter.setAuthFailureHandler(authFailureHandler);
		}
		ltpaFilter.afterPropertiesSet();
		builder.addFilterAt(ltpaFilter, AbstractPreAuthenticatedProcessingFilter.class);
	}

	/**
	 * configures the name of the cookie expected to contain the LTPA2 token
	 *
	 * @param cookieName the cookie name
	 * @return this instance
	 * @throws IllegalArgumentException if {@code cookieName} is empty
	 */
	public Ltpa2Configurer cookieName(@NonNull final String cookieName)
	{
		Assert.hasText(cookieName, "A cookieName is required");
		this.cookieName = cookieName;
		return this;
	}

	/**
	 * configures the name of the header expected to contain the LTPA2 token
	 *
	 * @param headerName the name of the header
	 * @return this instance
	 * @throws IllegalArgumentException if {@code headerName} is empty
	 */
	public Ltpa2Configurer headerName(@NonNull final String headerName)
	{
		Assert.hasText(headerName, "A headerName is required");
		this.headerName = headerName;
		return this;
	}
}
