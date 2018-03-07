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

import lombok.experimental.UtilityClass;

/**
 *
 * @author Sephiroth
 */
@UtilityClass
public class Constants
{
	/**
	 * base64-encoded and encrypted private key used to sign the tokens
	 */
	public final String ENCRYPTED_PRIVATE_KEY = "dP4F2H1MSphvjXHFnLqc1sUYiM83Mkg5MzCQWbxya0xMLPl6lwSbC9+SuCpbHTb9Qdl1w3d5bcDf400tBnfStdtkRYSOeo9oEbXOG4RqIV0x3WZx7AyJ5D8wVIfzOjgvfdQXqNkoiatyMwptvCytyEVbWH2kj3j0gB8O2/miPsbnZqNdIRDAt4TE2YjhVagC/ZP2xxxwncLDexF8Bme7NaMtJUlGMe8Nhkb61Z52PU2FHJAF6zPaTwj+JcZ/tg63lr5wRI9hGFOb7MhBrhgm9YiBqPOT30Crl28FHtTP9pnrqiC45QxU3aXVsYFh0hXptkkK9HeTk/YWFjDPVlfg9azrgGq64wHHg3cSjV21GAE=";

	/**
	 *base64-encoded public key which corresponds to {@link #ENCRYPTED_PRIVATE_KEY}
	 */
	public final String ENCODED_PUBLIC_KEY = "AOECPMDAs0o7MzQIgxZhAXJZ2BaDE3mqRZAbkbQO38CgUIgeAPEA3iWIYp+p/Ai0J4//UOml20an+AuCnDGzcFCaf3S3EAiR4cK59vl/u8TIswPIg2akh4J7qL3E/qRxN9WD945tS3h0YhJZSq7rC22wytLsxbFuKpEuYfm1i5spAQAB";

	/**
	 * base64-encoded and encrypted shared secret key used to encrypt and decrypt the tokens
	 */
	public final String ENCRYPTED_SHARED_KEY = "JvywHhxC+EhtUdeusbo31E5IUOEPmbMxMnKTTOB39fo=";

	/**
	 * password that has been used for encypting of {@link #ENCRYPTED_PRIVATE_KEY} and {@link #ENCRYPTED_SHARED_KEY}
	 */
	public final String ENCRYPTION_PASSWORD = "test123";
}
