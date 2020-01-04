/*
 * Copyright 2019 Sephiroth.
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
package de.sephirothj.spring.security.ltpa2.reactive;

import de.sephirothj.spring.security.ltpa2.Ltpa2Token;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SynchronousSink;

/**
 * Performs the final authentication of an {@link Authentication} instance previously created by {@link Ltpa2AuthConverter}.
 *
 * @author Sephiroth
 */
@RequiredArgsConstructor
@AllArgsConstructor
public class Ltpa2AuthManager implements ReactiveAuthenticationManager
{
	/**
	 * A ReactiveUserDetailsService required to lookup the user given in the provided Ltpa2Token
	 */
	@NonNull
	private final ReactiveUserDetailsService userDetailsService;

	/**
	 * An optional UserDetailsChecker such as {@link AccountStatusUserDetailsChecker}. It should throw an {@link AccountStatusException} in case somethings is not right with the {@link UserDetails}.
	 */
	@Nullable
	private UserDetailsChecker userDetailsChecker;

	/**
	 * Attempts to authenticate the provided {@link Authentication} with a {@link Ltpa2Token} as credentials
	 *
	 * @param authentication the {@link Authentication} to test
	 * @return If authentication is successful an {@link Authentication} is returned. If authentication cannot be determined, an empty Mono is returned. If authentication fails, a Mono error is returned.
	 */
	@Override
	public Mono<Authentication> authenticate(Authentication authentication)
	{
		return supports(authentication) ? Mono.just(authentication)
			.map(Authentication::getName)
			.flatMap(userDetailsService::findByUsername)
			.switchIfEmpty(Mono.error(() -> new UsernameNotFoundException("User not found")))
			.handle(this::checkUser)
			.map(user -> new PreAuthenticatedAuthenticationToken(user, null, user.getAuthorities()))
			: Mono.empty();
	}

	private void checkUser(final UserDetails user, final SynchronousSink<UserDetails> sink)
	{
		if (userDetailsChecker != null)
		{
			try
			{
				userDetailsChecker.check(user);
				sink.next(user);
			}
			catch (AccountStatusException e)
			{
				sink.error(e);
			}
		}
		else
		{
			sink.next(user);
		}
	}

	private boolean supports(final Authentication authentication)
	{
		return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication.getClass())
			&& Ltpa2Token.class.isAssignableFrom(authentication.getCredentials().getClass());
	}
}
