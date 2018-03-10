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

import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.junit.Test;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;

/**
 *
 * @author Sephiroth
 */
public class Ltpa2FilterTest
{
	@Test
	public void getTokenFromHeaderTestWithDefaultPrefix()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		String expected = "the-token";

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromHeader", "LtpaToken2 ".concat(expected));

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	public void getTokenFromHeaderTestWithCustomPrefix()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		String prefix = "my-prefix";
		uut.setHeaderValueIdentifier(prefix);
		String expected = "the-token";

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromHeader", prefix + expected);

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	public void getTokenFromHeaderTestWithEmptyPrefix()
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
	public void getTokenFromCookiesTestWithDefaultCookiename() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
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
	public void getTokenFromCookiesTestWithCustomCookiename() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
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
	public void getTokenFromRequestTestWithHeaderOnly()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		String expected = "the-token";
		BDDMockito.given(request.getHeader("Authorization")).willReturn("LtpaToken2 ".concat(expected));

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromRequest", request);

		assertThat(actual).isEqualTo(expected);
	}

	@Test
	public void getTokenFromRequestTestWithCookieOnly()
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		String expected = "the-token";
		Cookie[] cookies =
		{
			new Cookie("LtpaToken2", expected)
		};
		BDDMockito.given(request.getCookies()).willReturn(cookies);

		String actual = ReflectionTestUtils.invokeMethod(uut, "getTokenFromRequest", request);

		assertThat(actual).isEqualTo(expected);
	}

	@Test(expected = AuthenticationException.class)
	public void validateLtpaTokenAndLoadUserShouldRejectExpiredTokens() throws GeneralSecurityException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		String token = "Wl3qcMXdvCZjScDwB18/5VYujKDYsptVWXwNVW2yKuZw6h5Kg4amiGDeQCh2xmtNVPgCkzyk66ZWrdY70+nQEe+gotHjJtrcoW/VnbbQAwrQE5GojqK+1RdjvnwmQ9QULqcYAItw4ggZ2JF3CRR5uZ3NSFgkZpzkcMbfuYSWipNXsqEUHKONUlrg0Oc6lNKqWknx87HoPKmTnkGD5gdecu1FJCKUXSk1tanAjN3RaEWY8woxMIJQEMw/yeOrA9Fe+1nWjGAR5ITgkm+whpXfzl3n3g7kWHaBJf8DUUlKRsww4oCe3+t85b1WqoTC6FZw2qovLwn3ioRm1eIBDPO+KQZD60Ps4f+QEOjFzkLQC2f6BlZKc8KMHhffRQRpBgOD6kYV/wGDRHuvkK5vMAeJtQ==";

		ReflectionTestUtils.invokeMethod(uut, "validateLtpaTokenAndLoadUser", token);
	}

	@Test
	public void validateLtpaTokenAndLoadUserShouldAllowExpiredTokens() throws GeneralSecurityException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setAllowExpiredToken(true);
		final UserDetailsService mock = Mockito.mock(UserDetailsService.class);
		uut.setUserDetailsService(mock);
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		String token = "Wl3qcMXdvCZjScDwB18/5VYujKDYsptVWXwNVW2yKuZw6h5Kg4amiGDeQCh2xmtNVPgCkzyk66ZWrdY70+nQEe+gotHjJtrcoW/VnbbQAwrQE5GojqK+1RdjvnwmQ9QULqcYAItw4ggZ2JF3CRR5uZ3NSFgkZpzkcMbfuYSWipNXsqEUHKONUlrg0Oc6lNKqWknx87HoPKmTnkGD5gdecu1FJCKUXSk1tanAjN3RaEWY8woxMIJQEMw/yeOrA9Fe+1nWjGAR5ITgkm+whpXfzl3n3g7kWHaBJf8DUUlKRsww4oCe3+t85b1WqoTC6FZw2qovLwn3ioRm1eIBDPO+KQZD60Ps4f+QEOjFzkLQC2f6BlZKc8KMHhffRQRpBgOD6kYV/wGDRHuvkK5vMAeJtQ==";
		UserDetails mockUser = User.withUsername("test-user").roles("DEVELOPERS").password("dummy password").build();
		BDDMockito.given(mock.loadUserByUsername(anyString())).willReturn(mockUser);

		UserDetails actual = ReflectionTestUtils.invokeMethod(uut, "validateLtpaTokenAndLoadUser", token);
		assertThat(actual).isEqualTo(mockUser);
	}

	@Test(expected = AuthenticationException.class)
	public void validateLtpaTokenAndLoadUserShouldRejectInvalidSignatures() throws GeneralSecurityException
	{
		Ltpa2Filter uut = new Ltpa2Filter();
		uut.setAllowExpiredToken(true);
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		uut.setSignerKey(pair.getPublic());
		String token = "Wl3qcMXdvCZjScDwB18/5VYujKDYsptVWXwNVW2yKuZw6h5Kg4amiGDeQCh2xmtNVPgCkzyk66ZWrdY70+nQEe+gotHjJtrcoW/VnbbQAwrQE5GojqK+1RdjvnwmQ9QULqcYAItw4ggZ2JF3CRR5uZ3NSFgkZpzkcMbfuYSWipNXsqEUHKONUlrg0Oc6lNKqWknx87HoPKmTnkGD5gdecu1FJCKUXSk1tanAjN3RaEWY8woxMIJQEMw/yeOrA9Fe+1nWjGAR5ITgkm+whpXfzl3n3g7kWHaBJf8DUUlKRsww4oCe3+t85b1WqoTC6FZw2qovLwn3ioRm1eIBDPO+KQZD60Ps4f+QEOjFzkLQC2f6BlZKc8KMHhffRQRpBgOD6kYV/wGDRHuvkK5vMAeJtQ==";

		ReflectionTestUtils.invokeMethod(uut, "validateLtpaTokenAndLoadUser", token);
	}
}
