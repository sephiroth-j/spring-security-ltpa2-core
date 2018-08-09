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

import java.time.LocalDateTime;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 * @author Sephiroth
 */
public class Ltpa2TokenTest
{
	@Test
	public void testOf()
	{
		String serializedToken = "expire:1519043460000$attribute:value$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar";
		Ltpa2Token actual = Ltpa2Token.of(serializedToken);
		assertThat(actual).isNotNull();
		assertThat(actual.getAttribute(Ltpa2Token.USER_ATTRIBUTE_NAME)).isEqualTo("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
		assertThat(actual.getExpire()).isEqualTo(LocalDateTime.of(2018, 2, 19, 13, 31, 00));
		assertThat(actual.getAttribute("attribute")).isEqualTo("value");
	}
	
	@Test
	public void testToString()
	{
		Ltpa2Token token = new Ltpa2Token();
		token.withAttribute("attribute", "value");
		token.setUser("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
		token.setExpire(LocalDateTime.of(2018, 2, 21, 21, 49, 29));
		assertThat(token.toString()).isEqualTo("expire:1519246169000$attribute:value$u:user\\:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
	}
}
