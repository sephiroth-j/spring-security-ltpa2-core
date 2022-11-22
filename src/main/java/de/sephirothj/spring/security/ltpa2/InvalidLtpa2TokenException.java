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

import org.springframework.security.core.AuthenticationException;

/**
 * Exception thrown for all kinds of exceptions when working with an LTPA2 token or keys
 *
 * @author Sephiroth
 */
public class InvalidLtpa2TokenException extends AuthenticationException
{
	private static final long serialVersionUID = -1352184826130137850L;

	/**
	 * Constructs an {@code InvalidLtpa2TokenException} with the specified message and root cause.
	 *
	 * @param msg the detail message
	 * @param cause the root cause
	 */
	public InvalidLtpa2TokenException(String msg, Throwable cause)
	{
		super(msg, cause);
	}

	/**
	 * Constructs an {@code InvalidLtpa2TokenException} with the specified message and no root cause.
	 *
	 * @param msg the detail message
	 */
	public InvalidLtpa2TokenException(String msg)
	{
		super(msg);
	}
}
