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

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.regex.Pattern;
import lombok.Getter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * Represents an LTPA2-Token
 *
 * @author Sephiroth
 */
public class Ltpa2Token
{
	/**
	 * the well-known name for the attribute containing the username
	 */
	public static final String USER_ATTRIBUTE_NAME = "u";

	/**
	 * the well-known name for the attribute containing the expiration
	 */
	public static final String EXPIRE_ATTRIBUTE_NAME = "expire";

	private static final char BODY_PARTS_DELIMITER = '$';
	private static final String BODY_KEY_VALUE_DELIMITER = ":";
	private static final Pattern BODY_PARTS_PATTERN = Pattern.compile("\\$");

	/**
	 * Expiration of the token
	 */
	@Getter
	private LocalDateTime expire;

	/**
	 * user DN
	 */
	@Getter
	private String user;

	private final HashMap<String, String> additionalAttributes = new HashMap<>();

	/**
	 * sets the expiration of the token
	 *
	 * @param expire the (new) expiration date
	 */
	public void setExpire(@NonNull final LocalDateTime expire)
	{
		Assert.notNull(expire, "expire must not be null");
		this.expire = expire;
	}

	/**
	 * sets the expiration of the token
	 *
	 * @param expire the (new) expiration date in milliseconds since 01.01.1970T00:00:00Z
	 */
	public void setExpire(@NonNull final String expire)
	{
		Assert.hasText(expire, "expire must not be empty");
		this.expire = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.parseLong(expire)), ZoneId.systemDefault());
	}

	/**
	 * checks if this token is expired
	 *
	 * @return whether the token is expired or not
	 */
	public boolean isExpired()
	{
		return getExpire().isBefore(LocalDateTime.now());
	}

	/**
	 * sets the user of the token
	 *
	 * @param user the (new) user DN
	 */
	public void setUser(@NonNull final String user)
	{
		Assert.hasText(user, "user must not be empty");
		this.user = user;
	}

	/**
	 * <p>
	 * get the value of the specified attribute</p>
	 * <p>
	 * known attributes:</p>
	 * <ul>
	 * <li>u: same as {@link #user}</li>
	 * <li>expire: {@link #expire}</li>
	 * <li>host</li>
	 * <li>port</li>
	 * <li>java.naming.provider.url</li>
	 * <li>process.serverName</li>
	 * <li>security.authMechOID</li>
	 * <li>type</li>
	 * </ul>
	 *
	 * @param attribute the name of the attribute
	 * @return attribute value. may be {@code null}
	 */
	@Nullable
	public String getAttribute(@NonNull final String attribute)
	{
		Assert.notNull(attribute, "attribute must not be null");

		return switch (attribute)
		{
			case USER_ATTRIBUTE_NAME -> user;
			case EXPIRE_ATTRIBUTE_NAME -> expire != null ? String.valueOf(expire.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()) : null;
			default -> additionalAttributes.get(attribute);
		};
	}

	/**
	 * sets an attribute
	 *
	 * @param attribute the name of the attribute
	 * @param value attribute value
	 * @return this instance for chaining
	 */
	@NonNull
	public Ltpa2Token withAttribute(@NonNull final String attribute, @NonNull final String value)
	{
		Assert.notNull(attribute, "attribute must not be null");
		Assert.hasText(value, "value must not be empty");

		switch (attribute)
		{
			case USER_ATTRIBUTE_NAME -> setUser(value);
			case EXPIRE_ATTRIBUTE_NAME -> setExpire(value);
			default -> additionalAttributes.put(attribute, value);
		}
		return this;
	}

	/**
	 * gets the token as serialized (tokenized) string
	 *
	 * @return the serialized token
	 */
	@Override
	public String toString()
	{
		final StringBuilder sb = new StringBuilder();
		if (expire != null)
		{
			sb.append(EXPIRE_ATTRIBUTE_NAME).append(BODY_KEY_VALUE_DELIMITER).append(getAttribute(EXPIRE_ATTRIBUTE_NAME)).append(BODY_PARTS_DELIMITER);
		}
		additionalAttributes.forEach((key, value) -> sb.append(key).append(BODY_KEY_VALUE_DELIMITER).append(escapeValue(value)).append(BODY_PARTS_DELIMITER));
		sb.append(USER_ATTRIBUTE_NAME).append(BODY_KEY_VALUE_DELIMITER).append(escapeValue(user));
		return sb.toString();
	}

	/**
	 * creates a new instance out of serialized (tokenized) token
	 *
	 * @param serializedToken a serialized LTPA2 token (unencrypted)
	 * @return new instance
	 * @throws IllegalArgumentException if the given token is empty
	 */
	@NonNull
	public static Ltpa2Token of(@NonNull final String serializedToken)
	{
		Assert.hasText(serializedToken, "serializedToken must not be empty");

		final Ltpa2Token token = new Ltpa2Token();
		BODY_PARTS_PATTERN.splitAsStream(serializedToken).forEach(part ->
		{
			final String[] nameValue = part.split(BODY_KEY_VALUE_DELIMITER, 2);
			token.withAttribute(nameValue[0], unescapeValue(nameValue[1]));
		});
		return token;
	}

	/**
	 * escapes the special chars {@code :}, {@code $} and {@code % } with a preceding {@code \} in the given value
	 *
	 * @param value the value to escaped
	 * @return the value with special chars escaped
	 */
	@NonNull
	private static String escapeValue(@NonNull final String value)
	{
		return value.replaceAll("([\\:\\$\\%])", "\\\\$1");
	}

	/**
	 * unescape special chars in the given value
	 *
	 * @param value the value to unescape
	 * @return the value with special chars unescaped
	 * @see #escapeValue(java.lang.String)
	 */
	@NonNull
	private static String unescapeValue(@NonNull final String value)
	{
		return value.replaceAll("\\\\([\\:\\$\\%])", "$1");
	}
}
