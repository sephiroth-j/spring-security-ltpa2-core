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
import de.sephirothj.spring.security.ltpa2.LtpaKeyUtils;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.util.Base64Utils;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 * @author Sephiroth
 */
class Ltpa2AuthConverterTest
{

	@Test
	void getTokenFromHeaderTestWithDefaultPrefix() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);
		uut.afterPropertiesSet();

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(Constants.TEST_TOKEN));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.assertNext(this::verifyAuth)
			.verifyComplete();
	}

	@Test
	void getTokenFromHeaderTestWithCustomPrefix() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);
		String prefix = "my-prefix";
		uut.setHeaderValueIdentifier(prefix);

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, prefix.concat(Constants.TEST_TOKEN));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.assertNext(this::verifyAuth)
			.verifyComplete();
	}

	@Test
	void getTokenFromHeaderTestWithEmptyPrefix() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);
		uut.setHeaderValueIdentifier("");

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, Constants.TEST_TOKEN);
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.assertNext(this::verifyAuth)
			.verifyComplete();
	}

	@Test
	void getTokenFromHeaderTestWithCustomName() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);
		String headerName = "my-header";
		uut.setHeaderName(headerName);

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(headerName, "LtpaToken2 ".concat(Constants.TEST_TOKEN));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.assertNext(this::verifyAuth)
			.verifyComplete();
	}

	@Test
	void getTokenFromCookieTestWithDefaultName() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").cookie(new HttpCookie("LtpaToken2", Constants.TEST_TOKEN));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.assertNext(this::verifyAuth)
			.verifyComplete();
	}

	@Test
	void getTokenFromCookieTestWithCustomName() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);
		String cookieName = "my-cookie";
		uut.setCookieName(cookieName);

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").cookie(new HttpCookie(cookieName, Constants.TEST_TOKEN));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.assertNext(this::verifyAuth)
			.verifyComplete();
	}

	@Test
	void expiredTokenShouldBeRejected() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(Constants.TEST_TOKEN));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.verifyComplete();
	}

	@Test
	void invalidSignaturesShouldBeRejected() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		final SecretKey decryptSharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		uut.setSharedKey(decryptSharedKey);
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);

		String tokenWithInvalidSignature = "expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000%ipDldknyTbaSZluHTW3I/Dhh9veyi+QHoX3s4MPxvvTc09COCGGbOQLxiGoIqdBxDrv55WChFNDD6uUtnt74gNX2KTRQpbwY5zSMbNHkUrh/6X+OOqbvcR3fAmIBkTAyBwkX3u6T2WEoEq9FxOYpvlhqvygoJYrjM6JuQeGhvBB=";
		final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(decryptSharedKey.getEncoded());
		c.init(Cipher.ENCRYPT_MODE, decryptSharedKey, iv);
		final byte[] rawEncryptedToken = c.doFinal(tokenWithInvalidSignature.getBytes(StandardCharsets.UTF_8));
		String encryptedToken = Base64Utils.encodeToString(rawEncryptedToken);

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(encryptedToken));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.verifyComplete();
	}

	@Test
	void invalidTokensShouldBeRejected() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		uut.setSharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD));
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 asd");
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.verifyComplete();
	}

	@Test
	void malformedTokensShouldBeRejected() throws GeneralSecurityException
	{
		Ltpa2AuthConverter uut = new Ltpa2AuthConverter();
		final SecretKey decryptSharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		uut.setSharedKey(decryptSharedKey);
		uut.setSignerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY));
		uut.setAllowExpiredToken(true);

		String tokenWithMissingSignature = "expire:1519043460000$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar%1519043460000";
		final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		final IvParameterSpec iv = new IvParameterSpec(decryptSharedKey.getEncoded());
		c.init(Cipher.ENCRYPT_MODE, decryptSharedKey, iv);
		final byte[] rawEncryptedToken = c.doFinal(tokenWithMissingSignature.getBytes(StandardCharsets.UTF_8));
		String encryptedToken = Base64Utils.encodeToString(rawEncryptedToken);

		MockServerHttpRequest.BaseBuilder requestBuilder = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(encryptedToken));
		StepVerifier.create(uut.convert(MockServerWebExchange.from(requestBuilder.build())))
			.verifyComplete();
	}

	private void verifyAuth(Authentication auth)
	{
		assertThat(auth.isAuthenticated()).isFalse();
		assertThat(auth.getCredentials()).isInstanceOf(Ltpa2Token.class);
		assertThat(auth.getPrincipal()).isEqualTo(auth.getName()).asString().isEqualTo("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
	}
}
