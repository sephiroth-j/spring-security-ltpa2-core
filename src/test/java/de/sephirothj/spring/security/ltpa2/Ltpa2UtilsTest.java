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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import java.util.TimeZone;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 * @author Sephiroth
 */
public class Ltpa2UtilsTest
{
	@RegisterExtension
	static TimeZoneExtension tz = new TimeZoneExtension(TimeZone.getTimeZone("Europe/Berlin"));

	private static String getTestToken() throws GeneralSecurityException
	{
		SecretKey secretKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		String testToken = "Wl3qcMXdvCZjScDwB18/5VYujKDYsptVWXwNVW2yKuZw6h5Kg4amiGDeQCh2xmtNVPgCkzyk66ZWrdY70+nQEe+gotHjJtrcoW/VnbbQAwrQE5GojqK+1RdjvnwmQ9QULqcYAItw4ggZ2JF3CRR5uZ3NSFgkZpzkcMbfuYSWipNXsqEUHKONUlrg0Oc6lNKqWknx87HoPKmTnkGD5gdecu1FJCKUXSk1tanAjN3RaEWY8woxMIJQEMw/yeOrA9Fe+1nWjGAR5ITgkm+whpXfzl3n3g7kWHaBJf8DUUlKRsww4oCe3+t85b1WqoTC6FZw2qovLwn3ioRm1eIBDPO+KQZD60Ps4f+QEOjFzkLQC2f6BlZKc8KMHhffRQRpBgOD6kYV/wGDRHuvkK5vMAeJtQ==";
		return Ltpa2Utils.decryptLtpa2Token(testToken, secretKey);
	}

	@Test
	public void decryptLtpaToken2Test() throws GeneralSecurityException
	{
		String actual = getTestToken();

		assertThat(actual).contains("$");
		assertThat(actual).matches(".+%\\d+%.+");
		assertThat(actual).contains("u:");
		assertThat(actual).isEqualTo("expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000%ipDldknyTbaSZluHTW3I/Dhh9veyi+QHoX3s4MPxvvTc09COCGGbOQLxiGoIqdBxDrv55WChFNDD6uUtnt74gNX2KTRQpbwY5zSMbNHkUrh/6X+OOqbvcR3fAmIBkTAyBwkX3u6T2WEoEq9FxOYpvlhqvygoJYrjM6JuQeGhvqA=");
	}

	@Test
	public void decryptLtpaToken2TestWithMalformedToken() throws GeneralSecurityException
	{
		SecretKey secretKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		InvalidLtpa2TokenException expected = Assertions.assertThrows(InvalidLtpa2TokenException.class, () ->
		{
			Ltpa2Utils.decryptLtpa2Token("wekrcn kldgj", secretKey);
		});
		assertThat(expected).hasMessage("failed to decrypt LTPA2 token");
	}

	@Test
	public void makeInstanceTest() throws GeneralSecurityException
	{
		Ltpa2Token actual = Ltpa2Utils.makeInstance(getTestToken());

		assertThat(actual).isNotNull();
		assertThat(actual.getExpire()).isEqualToIgnoringNanos(LocalDateTime.of(2018, 2, 19, 13, 31));
		assertThat(actual.getUser()).isNotEmpty();
	}

	@Test
	public void makeInstanceTestWithEmptyExpire()
	{
		Ltpa2Token actual = Ltpa2Utils.makeInstance("u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000%2YN9in6ulaNSjOUoWyIYp1Sg4cF0BA5vL+Fn3wzNX/32DpokV8aAoJb2KV/6HhO6SbrswL1x5MudYFIxAo50CwymFqkYtvYe0aaYyjKrcPhJCih3acyLasZWUQQRU8iDSz8BAUwmztiY1YDZSRWCOAzZwdLOFTFhNhOoD+uV6nE=");

		assertThat(actual).isNotNull();
		assertThat(actual.getExpire()).isEqualToIgnoringNanos(LocalDateTime.of(2018, 2, 19, 13, 31));
		assertThat(actual.getUser()).isNotEmpty();
	}

	@Test
	public void makeInstanceTestWithMalformedToken()
	{
		InvalidLtpa2TokenException expected = Assertions.assertThrows(InvalidLtpa2TokenException.class, () ->
		{
			Ltpa2Utils.makeInstance("u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000");
		});
		assertThat(expected).hasMessage("token is malformed");
	}

	@Test
	public void isTokenExpiredTest() throws GeneralSecurityException
	{
		assertThat(Ltpa2Utils.isTokenExpired(getTestToken())).isTrue();
	}

	@Test
	public void isSignatureValidTest() throws GeneralSecurityException
	{
		assertThat(Ltpa2Utils.isSignatureValid(getTestToken(), Constants.ENCODED_PUBLIC_KEY)).isTrue();
	}

	@Test
	public void isSignatureValidTestWithInvalidPublicKey() throws GeneralSecurityException
	{
		InvalidLtpa2TokenException expected = Assertions.assertThrows(InvalidLtpa2TokenException.class, () ->
		{
			Ltpa2Utils.isSignatureValid(getTestToken(), "foo");
		});
		assertThat(expected).hasMessage("invalid public key");
	}

	@Test
	public void isSignatureValidTestWithMalformedToken() throws GeneralSecurityException
	{
		InvalidLtpa2TokenException expected = Assertions.assertThrows(InvalidLtpa2TokenException.class, () ->
		{
			Ltpa2Utils.isSignatureValid("u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000", Constants.ENCODED_PUBLIC_KEY);
		});
		assertThat(expected).hasMessage("token is malformed");
	}

	@Test
	public void signTokenTest() throws GeneralSecurityException
	{
		PrivateKey privKey = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);
		String sig = Ltpa2Utils.signToken("expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar", privKey);

		assertThat(sig).isEqualTo("ipDldknyTbaSZluHTW3I/Dhh9veyi+QHoX3s4MPxvvTc09COCGGbOQLxiGoIqdBxDrv55WChFNDD6uUtnt74gNX2KTRQpbwY5zSMbNHkUrh/6X+OOqbvcR3fAmIBkTAyBwkX3u6T2WEoEq9FxOYpvlhqvygoJYrjM6JuQeGhvqA=");
	}

	@Test
	public void encryptTokenTest() throws GeneralSecurityException
	{
		SecretKey sharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		PrivateKey privKey = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);
		Ltpa2Token token = new Ltpa2Token();
		token.setUser("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
		token.setExpire(LocalDateTime.of(2018, 2, 19, 13, 31, 00));

		String encrypted = Ltpa2Utils.encryptToken(token, privKey, sharedKey);

		assertThat(Ltpa2Utils.isSignatureValid(Ltpa2Utils.decryptLtpa2Token(encrypted, sharedKey), Constants.ENCODED_PUBLIC_KEY)).isTrue();
	}

	@Test
	public void encryptTokenTestWithMalformedSharedKey() throws GeneralSecurityException
	{
		SecretKey sharedKey = new SecretKeySpec(new byte[]
		{
			0
		}, "AES");
		PrivateKey privKey = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);
		Ltpa2Token token = new Ltpa2Token();
		token.setUser("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
		InvalidLtpa2TokenException expected = Assertions.assertThrows(InvalidLtpa2TokenException.class, () ->
		{
			Ltpa2Utils.encryptToken(token, privKey, sharedKey);
		});
		assertThat(expected).hasMessage("failed to encrypt token");
	}
}
