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

import java.io.IOException;
import java.security.PublicKey;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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
	@Setter
	private UserDetailsService userDetailsService;

	/**
	 * <p>
	 * the name of the cookie expected to contain the LTPA2 token</p>
	 * <p>
	 * default: {@code "LtpaToken2"}</p>
	 */
	@Setter
	private String cookieName = "LtpaToken2";

	/**
	 * <p>
	 * the name of header expected to contain the LTPA2 token</p>
	 * <p>
	 * default: {@code "Authorization"}</p>
	 */
	@Setter
	private String headerName = "Authorization";

	/**
	 * <p>
	 * the prefix in {@link #headername the header} preceding the LTPA2 token</p>
	 * <p>
	 * default: {@code cookieName + " "}</p>
	 *
	 * @see #cookieName
	 */
	@Setter
	private String headerValueIdentifier = cookieName + " ";

	/**
	 * the public key from the identity provider that sends the LTPA2-tokens. required for signature validation.
	 */
	@Setter
	private PublicKey signerKey;

	/**
	 * the shared secret key that is used to encrypt LTPA2 tokens
	 */
	@Setter
	private SecretKey sharedKey;

	/**
	 * allowed expired tokens
	 * <p>
	 * <b>Do not use in prodcution mode, only for testing!</b></p>
	 */
	@Setter
	private boolean allowExpiredToken = false;

	@Override
	public void afterPropertiesSet()
	{
		Assert.notNull(this.userDetailsService, "A UserDetailsService is required");
		Assert.hasText(this.cookieName, "A cookieName is required");
		Assert.hasText(this.headerName, "A headerName is required");
		Assert.hasText(this.headerValueIdentifier, "A headerValueIdentifier is required");
		Assert.notNull(this.signerKey, "A signerKey is required");
		Assert.notNull(this.sharedKey, "A sharedKey is required");
	}

	private String getTokenFromHeader(final String header)
	{
		return header != null && header.startsWith(headerValueIdentifier) ? header.substring(header.indexOf(headerValueIdentifier) + headerValueIdentifier.length()) : "";
	}

	private String getTokenFromCookies(final Cookie... cookies)
	{
		return cookies != null ? Stream.of(cookies).filter(c -> c.getName().equals(cookieName)).findFirst().map(c -> c.getValue()).orElse("") : "";
	}

	/**
	 * Get the LTPA2 token from the request. Either from the "Authorization" header or the Cookies.
	 *
	 * @param request
	 * @return the value of the LTPA2 token or empty string if none was found but never {@code null}
	 * @see #headerValueIdentifier
	 * @see #cookieName
	 */
	private String getTokenFromRequest(final HttpServletRequest request)
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
		String ltpaToken = getTokenFromRequest(request);
		log.debug("raw LTPA2 token: {}", ltpaToken);

		try
		{
			UserDetails user = validateLtpaTokenAndLoadUser(ltpaToken);
			Authentication authentication = new PreAuthenticatedAuthenticationToken(user, null, user.getAuthorities());
			SecurityContextHolder.getContext().setAuthentication(authentication);
			log.debug("User authenticated as '{}' with roles {}", user.getUsername(), user.getAuthorities());
		}
		catch (AuthenticationException invalidTokenEx)
		{
			SecurityContextHolder.clearContext();
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, invalidTokenEx.getLocalizedMessage());
			return;
		}

		filterChain.doFilter(request, response);
	}

	private UserDetails validateLtpaTokenAndLoadUser(final String encryptedToken) throws AuthenticationException
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
			Ltpa2Token token = Ltpa2Utils.makeInstance(ltpaToken);
			return userDetailsService.loadUserByUsername(token.getUser());
		}
		catch (AuthenticationException ex)
		{
			log.debug("User not found or token is malformed", ex);
			throw new InsufficientAuthenticationException("token invalid");
		}
	}
}
