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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 *
 * @author Sephiroth
 */
class Ltpa2UtilsTest
{
	@RegisterExtension
	static TimeZoneExtension tz = new TimeZoneExtension(TimeZone.getTimeZone("Europe/Berlin"));

	private static String getTestToken() throws GeneralSecurityException
	{
		SecretKey secretKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		return Ltpa2Utils.decryptLtpa2Token(Constants.TEST_TOKEN, secretKey);
	}

	@Test
	void decryptLtpaToken2Test() throws GeneralSecurityException
	{
		String actual = getTestToken();

		assertThat(actual)
			.contains("$")
			.matches(".+%\\d+%.+")
			.contains("u:")
			.isEqualTo("expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000%ipDldknyTbaSZluHTW3I/Dhh9veyi+QHoX3s4MPxvvTc09COCGGbOQLxiGoIqdBxDrv55WChFNDD6uUtnt74gNX2KTRQpbwY5zSMbNHkUrh/6X+OOqbvcR3fAmIBkTAyBwkX3u6T2WEoEq9FxOYpvlhqvygoJYrjM6JuQeGhvqA=");
	}

	@Test
	void decryptLtpaToken2TestWithMalformedToken() throws GeneralSecurityException
	{
		SecretKey secretKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		assertThatThrownBy(() ->
		{
			Ltpa2Utils.decryptLtpa2Token("wekrcn kldgj", secretKey);
		}).isExactlyInstanceOf(InvalidLtpa2TokenException.class).hasMessage("failed to decrypt LTPA2 token");
	}

	@Test
	void makeInstanceTest() throws GeneralSecurityException
	{
		Ltpa2Token actual = Ltpa2Utils.makeInstance(getTestToken());

		assertThat(actual).isNotNull();
		assertThat(actual.getExpire()).isEqualToIgnoringNanos(LocalDateTime.of(2018, 2, 19, 13, 31));
		assertThat(actual.getUser()).isNotEmpty();
	}

	@Test
	void makeInstanceTestWithEmptyExpire()
	{
		Ltpa2Token actual = Ltpa2Utils.makeInstance("u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000%2YN9in6ulaNSjOUoWyIYp1Sg4cF0BA5vL+Fn3wzNX/32DpokV8aAoJb2KV/6HhO6SbrswL1x5MudYFIxAo50CwymFqkYtvYe0aaYyjKrcPhJCih3acyLasZWUQQRU8iDSz8BAUwmztiY1YDZSRWCOAzZwdLOFTFhNhOoD+uV6nE=");

		assertThat(actual).isNotNull();
		assertThat(actual.getExpire()).isEqualToIgnoringNanos(LocalDateTime.of(2018, 2, 19, 13, 31));
		assertThat(actual.getUser()).isNotEmpty();
	}

	@Test
	void makeInstanceTestWithMalformedToken()
	{
		assertThatThrownBy(() ->
		{
			Ltpa2Utils.makeInstance("u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000");
		}).isExactlyInstanceOf(InvalidLtpa2TokenException.class).hasMessageContaining("invalid serialized LTPA2 token");
	}

	@Test
	void isTokenExpiredTest() throws GeneralSecurityException
	{
		assertThat(Ltpa2Utils.isTokenExpired(getTestToken())).isTrue();
	}

	@Test
	void isSignatureValidTest() throws GeneralSecurityException
	{
		assertThat(Ltpa2Utils.isSignatureValid(getTestToken(), Constants.ENCODED_PUBLIC_KEY)).isTrue();
	}

	@Test
	void isSignatureValidTestWithInvalidPublicKey() throws GeneralSecurityException
	{
		final String testToken = getTestToken();
		assertThatThrownBy(() ->
		{
			Ltpa2Utils.isSignatureValid(testToken, "foo");
		}).isExactlyInstanceOf(InvalidLtpa2TokenException.class).hasMessage("invalid public key");
	}

	@Test
	void isSignatureValidTestWithMalformedToken() throws GeneralSecurityException
	{
		assertThatThrownBy(() ->
		{
			Ltpa2Utils.isSignatureValid("u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000", Constants.ENCODED_PUBLIC_KEY);
		}).isExactlyInstanceOf(InvalidLtpa2TokenException.class).hasMessageContaining("invalid serialized LTPA2 token");
	}

	@Test
	void signTokenTest() throws GeneralSecurityException
	{
		PrivateKey privKey = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);
		String sig = Ltpa2Utils.signToken("expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar", privKey);

		assertThat(sig).isEqualTo("ipDldknyTbaSZluHTW3I/Dhh9veyi+QHoX3s4MPxvvTc09COCGGbOQLxiGoIqdBxDrv55WChFNDD6uUtnt74gNX2KTRQpbwY5zSMbNHkUrh/6X+OOqbvcR3fAmIBkTAyBwkX3u6T2WEoEq9FxOYpvlhqvygoJYrjM6JuQeGhvqA=");
	}

	@Test
	void encryptTokenTest() throws GeneralSecurityException
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
	void encryptTokenTestWithMalformedSharedKey() throws GeneralSecurityException
	{
		SecretKey sharedKey = new SecretKeySpec(new byte[]
		{
			0
		}, "AES");
		PrivateKey privKey = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);
		Ltpa2Token token = new Ltpa2Token();
		token.setUser("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
		assertThatThrownBy(() ->
		{
			Ltpa2Utils.encryptToken(token, privKey, sharedKey);
		}).isExactlyInstanceOf(InvalidLtpa2TokenException.class).hasMessage("failed to encrypt token");
	}
}
