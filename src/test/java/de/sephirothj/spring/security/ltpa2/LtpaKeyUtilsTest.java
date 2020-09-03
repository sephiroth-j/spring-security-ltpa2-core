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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 *
 * @author Sephiroth
 */
class LtpaKeyUtilsTest
{
	@Test
	void decryptSharedKeyTest() throws GeneralSecurityException
	{
		SecretKey actual = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);

		assertThat(actual).isNotNull();
		assertThat(actual.getAlgorithm()).isEqualTo("AES");
		assertThat(actual.getFormat()).isEqualTo("RAW");
	}

	@Test
	void decryptSharedKeyTestWithError()
	{
		assertThatThrownBy(() ->
		{
			LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, "foo");
		}).isInstanceOf(GeneralSecurityException.class).hasMessage("failed to decrypt shared key");
	}

	@Test
	void decodePublicKeyTest() throws GeneralSecurityException
	{
		PublicKey actual = LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY);

		assertThat(actual).isNotNull();
		assertThat(actual.getAlgorithm()).isEqualTo("RSA");
		assertThat(actual.getFormat()).isEqualTo("X.509");
	}

	@Test
	void decryptPrivateKeyTest() throws GeneralSecurityException
	{
		PrivateKey actual = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);

		assertThat(actual).isNotNull();
		assertThat(actual.getAlgorithm()).isEqualTo("RSA");
		assertThat(actual.getFormat()).isEqualTo("PKCS#8");
	}

	@Test
	void decryptPrivateKeyTestWithError() throws GeneralSecurityException
	{
		assertThatThrownBy(() ->
		{
			LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, "asdgh");
		}).isInstanceOf(GeneralSecurityException.class).hasMessage("failed to decrypt private key");
	}
}
