/*
 * Copyright 2018 Ronny "Sephiroth" Perinke <sephiroth@sephiroth-j.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.sephirothj.spring.security.ltpa2;

import java.security.PublicKey;
import javax.crypto.SecretKey;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

/**
 * <p>
 * A convenient way to configure pre-authentication using LTPA2-Tokens.</p>
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
 * <b>A {@link UserDetailsService} is required!</b> I case none no instance exposed, you have to provide one using {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder#userDetailsService(org.springframework.security.core.userdetails.UserDetailsService) AuthenticationManagerBuilder#userDetailsService}.</p>
 *
 * @author Sephiroth
 */
@Accessors(fluent = true)
public class Ltpa2Configurer extends AbstractHttpConfigurer<Ltpa2Configurer, HttpSecurity>
{
	/**
	 * <p>
	 * the name of the cookie containing the LTPA2-Token</p>
	 * <p>
	 * default: {@code "LtpaToken2"}</p>
	 */
	private String cookieName = "LtpaToken2";

	/**
	 * <p>
	 * the prefix in the Authorization header preceding the LTPA2-Token</p>
	 * <p>
	 * default: {@code cookieName + " "}</p>
	 *
	 * @see #cookieName
	 */
	private String headerValueIdentifier = cookieName + " ";

	/**
	 * the public key from the identity provider that sends the LTPA2-tokens. required for signature validation.
	 */
	@Setter
	@NonNull
	private PublicKey signerKey;

	/**
	 * the shared secret key that is used to encrypt LTPA2-Tokens
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

	@Override
	public void configure(HttpSecurity builder) throws Exception
	{
		UserDetailsService userDetailsService = builder.getSharedObject(UserDetailsService.class);
		Ltpa2Filter ltpaFilter = new Ltpa2Filter();
		ltpaFilter.setUserDetailsService(userDetailsService);
		ltpaFilter.setCookieName(cookieName);
		ltpaFilter.setHeaderValueIdentifier(headerValueIdentifier);
		ltpaFilter.setSharedKey(sharedKey);
		ltpaFilter.setSignerKey(signerKey);
		ltpaFilter.setAllowExpiredToken(allowExpiredToken);
		builder.addFilterAt(ltpaFilter, AbstractPreAuthenticatedProcessingFilter.class);
	}

	public Ltpa2Configurer cookieName(@NonNull final String cookieName)
	{
		Assert.hasText(cookieName, "A cookieName is required");
		this.cookieName = cookieName;
		headerValueIdentifier = cookieName + " ";
		return this;
	}

	public Ltpa2Configurer headerValueIdentifier(@NonNull final String headerValueIdentifier)
	{
		Assert.hasText(headerValueIdentifier, "A headerValueIdentifier is required");
		this.headerValueIdentifier = headerValueIdentifier;
		return this;
	}
}
