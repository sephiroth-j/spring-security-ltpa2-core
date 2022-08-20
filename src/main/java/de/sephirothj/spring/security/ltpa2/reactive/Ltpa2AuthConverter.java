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

import de.sephirothj.spring.security.ltpa2.Ltpa2Token;
import de.sephirothj.spring.security.ltpa2.Ltpa2Utils;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SynchronousSink;

/**
 * Strategy for converting a {@link ServerWebExchange} to an {@link Authentication} based on LTPA2 tokens. The final authentication will be done by a {@link Ltpa2AuthManager}. The token is expected to be given in the header {@link #headerName} with an {@link #headerValueIdentifier optional prefix}. If the header is empty or not found the token will be searched in the cookie named {@link #cookieName}.
 *
 * @author Sephiroth
 */
@Slf4j
public class Ltpa2AuthConverter implements ServerAuthenticationConverter, InitializingBean
{
	/**
	 * <p>
	 * the name of the cookie expected to contain the LTPA2 token</p>
	 * <p>
	 * default: {@code "LtpaToken2"}</p>
	 */
	@Setter
	@NonNull
	private String cookieName = "LtpaToken2";

	/**
	 * <p>
	 * the name of header expected to contain the LTPA2 token</p>
	 * <p>
	 * default: {@value HttpHeaders#AUTHORIZATION}</p>
	 */
	@Setter
	@NonNull
	private String headerName = HttpHeaders.AUTHORIZATION;

	/**
	 * <p>
	 * the prefix in {@link #headername the header} preceding the LTPA2 token</p>
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
	 * allow expired tokens
	 * <p>
	 * <b>Do not use in prodcution mode, only for testing!</b></p>
	 */
	@Setter
	private boolean allowExpiredToken = false;

	@Override
	public void afterPropertiesSet()
	{
		Assert.hasText(cookieName, "A cookieName is required");
		Assert.hasText(headerName, "A headerName is required");
		Assert.notNull(headerValueIdentifier, "The headerValueIdentifier must not be null");
		Assert.notNull(signerKey, "A signerKey is required");
		Assert.notNull(sharedKey, "A sharedKey is required");
		if (allowExpiredToken)
		{
			log.warn("Expired LTPA2 tokens are allowed, this should only be used for testing!");
		}
	}

	private void checkForExpiredToken(final String ltpaToken, final SynchronousSink<String> sink)
	{
		try
		{
			if (!Ltpa2Utils.isTokenExpired(ltpaToken) || allowExpiredToken)
			{
				sink.next(ltpaToken);
			}
			else
			{
				throw new InsufficientAuthenticationException("token expired");
			}
		}
		catch (AuthenticationException e)
		{
			// do not produce mono error, just log and produce empty mono as by contract of ServerAuthenticationConverter
			log.warn(e.getLocalizedMessage(), e);
		}
	}

	private void checkTokenSignature(final String ltpaToken, final SynchronousSink<String> sink)
	{
		try
		{
			if (Ltpa2Utils.isSignatureValid(ltpaToken, signerKey))
			{
				sink.next(ltpaToken);
			}
			else
			{
				throw new InsufficientAuthenticationException("token signature invalid");
			}
		}
		catch (AuthenticationException e)
		{
			// do not produce mono error, just log and produce empty mono as by contract of ServerAuthenticationConverter
			log.warn(e.getLocalizedMessage(), e);
		}
	}

	/**
	 * Extracts an LTAP2 token from the defined {@link #headerName header} or {@link #cookieName cookie} (as fallback), validates it and if it is, creates an {@link Authentication} instance with it
	 *
	 * @param exchange The {@link ServerWebExchange}
	 * @return A {@link Mono} representing an {@link Authentication} with a valid {@link Ltpa2Token} as credentials or an empty Mono if the token was not found or is invalid
	 */
	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange)
	{
		final ServerHttpRequest request = exchange.getRequest();
		return Mono.justOrEmpty(request.getHeaders().getFirst(headerName))
			.filter(header -> !header.isEmpty() && header.startsWith(headerValueIdentifier))
			.map(header -> header.substring(header.indexOf(headerValueIdentifier) + headerValueIdentifier.length()))
			// try cookie as fallback
			.switchIfEmpty(Mono.defer(() -> Mono.justOrEmpty(request.getCookies().getFirst(cookieName)).map(HttpCookie::getValue)))
			.doOnNext(encryptedToken -> log.debug("raw LTPA2 token: {}", encryptedToken))
			.map(encryptedToken -> Ltpa2Utils.decryptLtpa2Token(encryptedToken, sharedKey))
			.onErrorResume(e ->
			{
				log.warn(e.getLocalizedMessage(), e);
				return Mono.empty();
			})
			.handle(this::checkForExpiredToken)
			.handle(this::checkTokenSignature)
			.map(Ltpa2Utils::makeInstance)
			.map(token -> new PreAuthenticatedAuthenticationToken(token.getUser(), token));
	}

}
