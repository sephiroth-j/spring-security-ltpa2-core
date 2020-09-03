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
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.Base64Utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 *
 * @author Sephiroth
 */
class Ltpa2FilterTest
{
	
	@Test
	void getTokenFromHeaderTestWithDefaultPrefix()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		String expected = "the-token";

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromHeader", "LtpaToken2 ".concat(expected));

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void getTokenFromHeaderTestWithCustomPrefix()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		String prefix = "my-prefix";
		uut.setHeaderValueIdentifier(prefix);
		String expected = "the-token";

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromHeader", prefix + expected);

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void getTokenFromHeaderTestWithEmptyPrefix()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setHeaderValueIdentifier("");
		uut.setUserDetailsService(Mockito.mock(UserDetailsService.class));
		uut.setSharedKey(Mockito.mock(SecretKey.class));
		uut.setSignerKey(Mockito.mock(PublicKey.class));
		uut.afterPropertiesSet();
		String expected = "the-token";

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromHeader", expected);

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void getTokenFromCookiesTestWithDefaultCookiename() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		String expected = "the-token";

		Cookie[] cookies =
		{
			new Cookie("other", "whatever"), new Cookie("LtpaToken2", expected), new Cookie("3rd", "value of 3rd")
		};

		// that strange looking thing with Object[] is required because of the vararg method signature
		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromCookies", new Object[]
		{
			cookies
		});

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void getTokenFromCookiesTestWithCustomCookiename() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		String name = "my-cookie";
		uut.setCookieName(name);
		String expected = "the-token";

		Cookie[] cookies =
		{
			new Cookie("other", "whatever"), new Cookie(name, expected), new Cookie("3rd", "value of 3rd")
		};

		// that strange looking thing with Object[] is required because of the vararg method signature
		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromCookies", new Object[]
		{
			cookies
		});

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void getTokenFromRequestTestWithHeaderOnly()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		String expected = "the-token";
		given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("LtpaToken2 ".concat(expected));

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromRequest", request);

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void getTokenFromRequestTestWithCookieOnly()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		String expected = "the-token";
		Cookie[] cookies =
		{
			new Cookie("LtpaToken2", expected)
		};
		given(request.getCookies()).willReturn(cookies);

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromRequest", request);

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	void validateLtpaTokenAndLoadUserShouldRejectExpiredTokens() throws GeneralSecurityException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));

		AuthenticationException expected = Assertions.assertThrows(InsufficientAuthenticationException.class, () ->
		{
			ReflectionTestUtils.invokeMethod(uut, "validateLtpaTokenAndLoadUser", Constants.TEST_TOKEN);
		});
		assertThat(expected).hasMessage("token expired");
	}

	@Test
	void validateLtpaTokenAndLoadUserShouldAllowExpiredTokens() throws GeneralSecurityException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setAllowExpiredToken(true);
		final UserDetailsService mock = Mockito.mock(UserDetailsService.class);
		uut.setUserDetailsService(mock);
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		UserDetails mockUser = User.withUsername("test-user").roles("DEVELOPERS").password("dummy password").build();
		given(mock.loadUserByUsername(anyString())).willReturn(mockUser);

		UserDetails actual = ReflectionTestUtils.invokeMethod(uut, "validateLtpaTokenAndLoadUser", Constants.TEST_TOKEN);
		assertThat(actual).isEqualTo(mockUser);
	}

	@Test
	void validateLtpaTokenAndLoadUserShouldRejectInvalidSignatures() throws GeneralSecurityException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setAllowExpiredToken(true);
		final SecretKey decryptSharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		uut.setSharedKey(decryptSharedKey);
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		
		String tokenWithInvalidSignature = "expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000%ipDldknyTbaSZluHTW3I/Dhh9veyi+QHoX3s4MPxvvTc09COCGGbOQLxiGoIqdBxDrv55WChFNDD6uUtnt74gNX2KTRQpbwY5zSMbNHkUrh/6X+OOqbvcR3fAmIBkTAyBwkX3u6T2WEoEq9FxOYpvlhqvygoJYrjM6JuQeGhvBB=";
		final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(decryptSharedKey.getEncoded());
		c.init(Cipher.ENCRYPT_MODE, decryptSharedKey, iv);
		final byte[] rawEncryptedToken = c.doFinal(tokenWithInvalidSignature.getBytes(StandardCharsets.UTF_8));
		String encryptedToken = Base64Utils.encodeToString(rawEncryptedToken);

		AuthenticationException expected = Assertions.assertThrows(InsufficientAuthenticationException.class, () ->
		{
			ReflectionTestUtils.invokeMethod(uut, "validateLtpaTokenAndLoadUser", encryptedToken);
		});
		assertThat(expected).hasMessage("token signature invalid");
	}

	@Test
	void shouldNotFilterTestWithEmptyHeadersAndCookies() throws ServletException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		assertThat(uut.shouldNotFilter(request)).isTrue();
	}

	@Test
	void shouldNotFilterTestWithHeaderOnly() throws ServletException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("LtpaToken2 dummy-token");
		assertThat(uut.shouldNotFilter(request)).isFalse();
	}

	@Test
	void shouldNotFilterTestWithCookieIOnly() throws ServletException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		given(request.getCookies()).will(i -> new Cookie[]
		{
			new Cookie("LtpaToken2", "dummy-token")
		});
		assertThat(uut.shouldNotFilter(request)).isFalse();
	}

	@Test
	void doFilterInternalShouldSetAuthentication() throws ServletException, IOException, GeneralSecurityException
	{
		HttpServletRequest request = MockMvcRequestBuilders.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(Constants.TEST_TOKEN)).buildRequest(new MockServletContext());
		UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
		UserDetails mockUser = User.withUsername("test-user").roles("DEVELOPERS").password("dummy password").build();
		given(userDetailsService.loadUserByUsername(anyString())).willReturn(mockUser);
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setAllowExpiredToken(true);
		uut.setUserDetailsService(userDetailsService);
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));

		uut.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		verify(userDetailsService).loadUserByUsername(anyString());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isInstanceOf(PreAuthenticatedAuthenticationToken.class).satisfies(auth ->
		{
			assertThat(auth.getPrincipal()).isEqualTo(mockUser);
			assertThat(auth.getAuthorities()).containsExactlyInAnyOrderElementsOf((Iterable) mockUser.getAuthorities());
		});
	}

	@Test
	void doFilterInternalShouldCause403ForUnknownUsers() throws ServletException, IOException, GeneralSecurityException
	{
		HttpServletRequest request = MockMvcRequestBuilders.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(Constants.TEST_TOKEN)).buildRequest(new MockServletContext());
		HttpServletResponse response = new MockHttpServletResponse();
		UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
		given(userDetailsService.loadUserByUsername(anyString())).willThrow(UsernameNotFoundException.class);
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setAllowExpiredToken(true);
		uut.setUserDetailsService(userDetailsService);
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));

		uut.doFilter(request, response, new MockFilterChain());

		verify(userDetailsService).loadUserByUsername(anyString());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}
}
