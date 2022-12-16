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

import java.security.PublicKey;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import static org.assertj.core.api.Assertions.assertThat;
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
		ApplicationContext context = mock(ApplicationContext.class);
		HttpSecurity httpSecurity = mock(HttpSecurity.class);
		UserDetailsService userDetailsService = mock(UserDetailsService.class);
		given(httpSecurity.getSharedObject(ApplicationContext.class)).will(invocation -> context);
		given(context.getBean(UserDetailsService.class)).will(invocation -> userDetailsService);
		final String headerName = "header";
		final String cookieName = "cookie";
		final SecretKey sharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		final PublicKey publicKey = LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY);
		
		new Ltpa2Configurer()
			.headerName(headerName)
			.cookieName(cookieName)
			.allowExpiredToken(true)
			.sharedKey(sharedKey)
			.signerKey(publicKey)
			.configure(httpSecurity);
		
		ArgumentCaptor<Ltpa2Filter> configuredFilter = ArgumentCaptor.forClass(Ltpa2Filter.class);
		verify(httpSecurity).addFilterAt(configuredFilter.capture(), eq(AbstractPreAuthenticatedProcessingFilter.class));
		assertThat(configuredFilter.getValue())
			.hasFieldOrPropertyWithValue("headerName", headerName)
			.hasFieldOrPropertyWithValue("headerValueIdentifier", "LtpaToken2 ")
			.hasFieldOrPropertyWithValue("cookieName", cookieName)
			.hasFieldOrPropertyWithValue("allowExpiredToken", true)
			.hasFieldOrPropertyWithValue("sharedKey", sharedKey)
			.hasFieldOrPropertyWithValue("signerKey", publicKey)
			.extracting("authFailureHandler").isNotNull()
			;
	}

	@Test
	void testConfigureWithAuthFaulureHandler() throws Exception
	{
		ApplicationContext context = mock(ApplicationContext.class);
		HttpSecurity httpSecurity = mock(HttpSecurity.class);
		UserDetailsService userDetailsService = mock(UserDetailsService.class);
		given(httpSecurity.getSharedObject(ApplicationContext.class)).will(invocation -> context);
		given(context.getBean(UserDetailsService.class)).will(invocation -> userDetailsService);
		final SecretKey sharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		final PublicKey publicKey = LtpaKeyUtils.decodePublicKey(Constants.ENCODED_PUBLIC_KEY);
		final AuthenticationFailureHandler failureHandler = new AuthenticationEntryPointFailureHandler(new Http403ForbiddenEntryPoint());
		
		new Ltpa2Configurer()
			.sharedKey(sharedKey)
			.signerKey(publicKey)
			.authFailureHandler(failureHandler)
			.configure(httpSecurity);
		
		ArgumentCaptor<Ltpa2Filter> configuredFilter = ArgumentCaptor.forClass(Ltpa2Filter.class);
		verify(httpSecurity).addFilterAt(configuredFilter.capture(), eq(AbstractPreAuthenticatedProcessingFilter.class));
		assertThat(configuredFilter.getValue())
			.hasFieldOrPropertyWithValue("headerName", "Authorization")
			.hasFieldOrPropertyWithValue("headerValueIdentifier", "LtpaToken2 ")
			.hasFieldOrPropertyWithValue("cookieName", "LtpaToken2")
			.hasFieldOrPropertyWithValue("allowExpiredToken", false)
			.hasFieldOrPropertyWithValue("sharedKey", sharedKey)
			.hasFieldOrPropertyWithValue("signerKey", publicKey)
			.hasFieldOrPropertyWithValue("authFailureHandler", failureHandler)
			;
	}
}
