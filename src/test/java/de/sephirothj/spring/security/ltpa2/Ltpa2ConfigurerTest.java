/*
 * Copyright 2018 Sephiroth.
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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 *
 * @author Sephiroth
 */
class Ltpa2ConfigurerTest
{
	@Test
	void testConfigure() throws Exception
	{
		HttpSecurity httpSecurity = mock(HttpSecurity.class);
		given(httpSecurity.getSharedObject(eq(UserDetailsService.class))).will((invocation) -> mock(invocation.getArgument(0)));
		
		new Ltpa2Configurer()
			.headerName("header")
			.cookieName("cookie")
			.allowExpiredToken(true)
			.sharedKey(LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD))
			.signerKey(LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY))
			.configure(httpSecurity);
		
		verify(httpSecurity).addFilterAt(ArgumentMatchers.isA(Ltpa2Filter.class), eq(AbstractPreAuthenticatedProcessingFilter.class));
	}
}
