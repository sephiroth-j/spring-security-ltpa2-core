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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.junit.Test;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

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
}
