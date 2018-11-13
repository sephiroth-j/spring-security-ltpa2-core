/*
 * Copyright 2018 Sephiroth.
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

import java.util.TimeZone;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Run the test class in the specified timezone
 *
 * @author Sephiroth
 */
@RequiredArgsConstructor
@Getter
public final class TimeZoneExtension implements BeforeAllCallback, AfterAllCallback
{
	/**
	 * the Timezone to use for the test
	 */
	private final TimeZone tz;
	
	private TimeZone previousZone;

	@Override
	public void beforeAll(ExtensionContext context) throws Exception
	{
		previousZone = TimeZone.getDefault();
		TimeZone.setDefault(tz);
	}

	@Override
	public void afterAll(ExtensionContext context) throws Exception
	{
		TimeZone.setDefault(previousZone);
	}

}
