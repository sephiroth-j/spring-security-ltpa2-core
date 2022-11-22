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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The pre-authentication filter for LTPA2 tokens. The token is expected to be given in the header {@link #headerName} with an {@link #headerValueIdentifier optional prefix}. If the header is empty or not found the token will be searched in the cookie named {@link #cookieName}.
 *
 * @author Sephiroth
 */
@Slf4j
public final class Ltpa2Filter extends OncePerRequestFilter
{
	private static final String EMPTY_STRING = "";

	@Setter
	@NonNull
	private UserDetailsService userDetailsService;

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

	/**
	 * allows to change the default behaviour when an authentication failure occurs.
	 * <p>
	 * The default is to respond with 403 status code</p>
	 */
	@Setter
	@NonNull
	private AuthenticationFailureHandler authFailureHandler = (request, response, exception) -> response.sendError(HttpStatus.FORBIDDEN.value(), "Access Denied");

	@Override
	public void afterPropertiesSet()
	{
		Assert.notNull(userDetailsService, "A UserDetailsService is required");
		Assert.hasText(cookieName, "A cookieName is required");
		Assert.hasText(headerName, "A headerName is required");
		Assert.notNull(headerValueIdentifier, "The headerValueIdentifier must not be null");
		Assert.notNull(signerKey, "A signerKey is required");
		Assert.notNull(sharedKey, "A sharedKey is required");
		Assert.notNull(authFailureHandler, "An authFailureHandler is required");
		if (allowExpiredToken)
		{
			log.warn("Expired LTPA2 tokens are allowed, this should only be used for testing!");
		}
	}

	@NonNull
	private String getTokenFromHeader(@Nullable final String header)
	{
		return header != null && header.startsWith(headerValueIdentifier) ? header.substring(header.indexOf(headerValueIdentifier) + headerValueIdentifier.length()) : EMPTY_STRING;
	}

	@NonNull
	private String getTokenFromCookies(@Nullable final Cookie... cookies)
	{
		return cookies != null ? Stream.of(cookies).filter(c -> c.getName().equals(cookieName)).findFirst().map(Cookie::getValue).orElse(EMPTY_STRING) : EMPTY_STRING;
	}

	/**
	 * Get the LTPA2 token from the request. Either from {@linkplain #headerName the header} or {@linkplain #cookieName a cookie}.
	 *
	 * @param request
	 * @return the value of the LTPA2 token or empty string if none was found but never {@code null}
	 */
	@NonNull
	private String getTokenFromRequest(@NonNull final HttpServletRequest request)
	{
		String ltpaToken = getTokenFromHeader(request.getHeader(headerName));
		if (ltpaToken.isEmpty())
		{
			ltpaToken = getTokenFromCookies(request.getCookies());
		}
		return ltpaToken;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException
	{
		return getTokenFromRequest(request).isEmpty();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
	{
		final String ltpaToken = getTokenFromRequest(request);
		log.debug("raw LTPA2 token: {}", ltpaToken);

		try
		{
			final UserDetails user = validateLtpaTokenAndLoadUser(ltpaToken);
			final Authentication authentication = new PreAuthenticatedAuthenticationToken(user, null, user.getAuthorities());
			SecurityContextHolder.getContext().setAuthentication(authentication);
			log.debug("User authenticated as '{}' with roles {}", user.getUsername(), user.getAuthorities());
		}
		catch (AuthenticationException invalidTokenEx)
		{
			SecurityContextHolder.clearContext();
			authFailureHandler.onAuthenticationFailure(request, response, invalidTokenEx);
			return;
		}

		filterChain.doFilter(request, response);
	}

	/**
	 * Verifies the given token and if it is, the method will return a {@linkplain UserDetails user record} with the help of the {@linkplain #userDetailsService configured UserDetailsService}.
	 *
	 * @param encryptedToken the encrpyted token that sould be verified
	 * @return a user record but never {@code null}
	 * @throws AuthenticationException if the token was malformed
	 * @throws InsufficientAuthenticationException if the token is expired
	 * @throws InsufficientAuthenticationException if the token signature is invalid
	 * @throws AuthenticationException if the user was not found or has not granted authorities
	 */
	@NonNull
	private UserDetails validateLtpaTokenAndLoadUser(@NonNull final String encryptedToken) throws AuthenticationException
	{
		final String ltpaToken = Ltpa2Utils.decryptLtpa2Token(encryptedToken, sharedKey);
		if (Ltpa2Utils.isTokenExpired(ltpaToken) && !allowExpiredToken)
		{
			throw new InsufficientAuthenticationException("token expired");
		}

		if (!Ltpa2Utils.isSignatureValid(ltpaToken, signerKey))
		{
			throw new InsufficientAuthenticationException("token signature invalid");
		}

		try
		{
			final Ltpa2Token token = Ltpa2Utils.makeInstance(ltpaToken);
			return userDetailsService.loadUserByUsername(token.getUser());
		}
		catch (AuthenticationException ex)
		{
			log.debug(ex instanceof UsernameNotFoundException ? "User not found" : "token is malformed", ex);
			throw new InsufficientAuthenticationException("token invalid", ex);
		}
	}
}
