/*
 * Copyright 2019 Sephiroth.
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
package de.sephirothj.spring.security.ltpa2.reactive;

import de.sephirothj.spring.security.ltpa2.Constants;
import de.sephirothj.spring.security.ltpa2.Ltpa2Token;
import de.sephirothj.spring.security.ltpa2.Ltpa2Utils;
import de.sephirothj.spring.security.ltpa2.LtpaKeyUtils;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

/**
 *
 * @author Sephiroth
 */
class Ltpa2AuthManagerTest
{
	private static Ltpa2Token getTestToken() throws GeneralSecurityException
	{
		SecretKey secretKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		return Ltpa2Utils.makeInstance(Ltpa2Utils.decryptLtpa2Token(Constants.TEST_TOKEN, secretKey));
	}

	@Test
	void authenticateTest() throws GeneralSecurityException, Exception
	{
		ReactiveUserDetailsService userDetailsService = Mockito.mock(ReactiveUserDetailsService.class);
		final UserDetails mockUser = User.withUsername("test").password("password").roles("tester").build();
		given(userDetailsService.findByUsername(anyString())).willReturn(Mono.just(mockUser));
		Ltpa2AuthManager uut = new Ltpa2AuthManager(userDetailsService);
		Ltpa2Token token = getTestToken();

		StepVerifier.create(uut.authenticate(new PreAuthenticatedAuthenticationToken(token.getUser(), token)))
			.assertNext(auth ->
			{
				assertThat(auth.isAuthenticated()).isTrue();
				assertThat(auth.getCredentials()).isNull();
				assertThat(auth.getPrincipal()).isEqualTo(mockUser);
			})
			.verifyComplete();
	}

	@Test
	void authenticateTestWithUserChecker() throws GeneralSecurityException, Exception
	{
		ReactiveUserDetailsService userDetailsService = Mockito.mock(ReactiveUserDetailsService.class);
		final UserDetails mockUser = User.withUsername("test").password("password").roles("tester").build();
		given(userDetailsService.findByUsername(anyString())).willReturn(Mono.just(mockUser));
		Ltpa2AuthManager uut = new Ltpa2AuthManager(userDetailsService, new AccountStatusUserDetailsChecker());
		Ltpa2Token token = getTestToken();

		StepVerifier.create(uut.authenticate(new PreAuthenticatedAuthenticationToken(token.getUser(), token)))
			.assertNext(auth ->
			{
				assertThat(auth.isAuthenticated()).isTrue();
				assertThat(auth.getCredentials()).isNull();
				assertThat(auth.getPrincipal()).isEqualTo(mockUser);
			})
			.verifyComplete();
	}

	@Test
	void authenticateTestWithUserCheckerAndLockedAccout() throws GeneralSecurityException, Exception
	{
		ReactiveUserDetailsService userDetailsService = Mockito.mock(ReactiveUserDetailsService.class);
		final UserDetails mockUser = User.withUsername("test").password("password").roles("tester").accountLocked(true).build();
		given(userDetailsService.findByUsername(anyString())).willReturn(Mono.just(mockUser));
		Ltpa2AuthManager uut = new Ltpa2AuthManager(userDetailsService, new AccountStatusUserDetailsChecker());
		Ltpa2Token token = getTestToken();

		StepVerifier.create(uut.authenticate(new PreAuthenticatedAuthenticationToken(token.getUser(), token)))
			.verifyError(LockedException.class);
	}

	@Test
	void authenticateWithUnknownUserTest() throws GeneralSecurityException, Exception
	{
		ReactiveUserDetailsService userDetailsService = Mockito.mock(ReactiveUserDetailsService.class);
		given(userDetailsService.findByUsername(anyString())).willReturn(Mono.empty());
		Ltpa2AuthManager uut = new Ltpa2AuthManager(userDetailsService);
		Ltpa2Token token = getTestToken();

		StepVerifier.create(uut.authenticate(new PreAuthenticatedAuthenticationToken(token.getUser(), token)))
			.verifyErrorSatisfies(t ->
			{
				assertThat(t).isInstanceOf(UsernameNotFoundException.class).hasMessage("User not found");
			});
	}

	@Test
	void authenticateWithUnsupportedAuthTest() throws GeneralSecurityException, Exception
	{
		ReactiveUserDetailsService userDetailsService = Mockito.mock(ReactiveUserDetailsService.class);
		given(userDetailsService.findByUsername(anyString())).willReturn(Mono.empty());
		Ltpa2AuthManager uut = new Ltpa2AuthManager(userDetailsService);

		StepVerifier.create(uut.authenticate(new PreAuthenticatedAuthenticationToken("test", "test")))
			.verifyComplete();
	}
}
