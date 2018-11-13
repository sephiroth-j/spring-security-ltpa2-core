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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;
import org.springframework.lang.NonNull;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;

/**
 * Utility class for working with encoded and/or encrpyted keys exported from IBM WebSphere Application Server and Liberty Profile
 *
 * @author Sephiroth
 */
@UtilityClass
public class LtpaKeyUtils
{
	private static final String PASSWORD_MUST_NOT_BE_EMPTY = "password must not be empty";

	/**
	 * the size of the shared secret key in byte
	 */
	private static final byte SHARED_KEY_SIZE = 16;

	/**
	 * the length of the field with the public modulus
	 */
	private static final int PUBLIC_MODULUS_LENGTH = 129;

	/**
	 * the length of the field with the public exponent
	 */
	private static final byte PUBLIC_EXPONENT_LENGTH = 3;

	/**
	 * the length of the fields for the private factors Q and P
	 */
	private static final byte PRIVATE_P_Q_LENGTH = 65;

	/**
	 * the length of the field that contains the length of the private exponent
	 */
	private static final byte PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH = 4;

	/**
	 * decrypts something that was encrypted using the IBM-specific methods, such as the shared secret key and the private key
	 *
	 * @param encrypted
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] decrypt(@NonNull final byte[] encrypted, @NonNull final String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
	{
		Assert.notNull(encrypted, "encrypted must not be null");
		Assert.hasText(password, PASSWORD_MUST_NOT_BE_EMPTY);
		
		final MessageDigest md = MessageDigest.getInstance("SHA");
		final byte[] pwdHash = Arrays.copyOfRange(md.digest(password.getBytes()), 0, 24);
		final Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		final Key decryptionKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(pwdHash));
		c.init(Cipher.DECRYPT_MODE, decryptionKey);
		return c.doFinal(encrypted);
	}

	/**
	 * decrypts the shared secret key ({@code com.ibm.websphere.ltpa.3DESKey}) that is used to encrypt a serialized LTPA2 token
	 *
	 * @param encryptedKey the base64-encoded and with 3DES encrypted key
	 * @param password the password for decryption (attribute {@code keysPassword} in your server configuration)
	 * @return the decrypted key
	 * @throws GeneralSecurityException if anything went wrong
	 */
	@NonNull
	public SecretKey decryptSharedKey(@NonNull final String encryptedKey, @NonNull final String password) throws GeneralSecurityException
	{
		Assert.notNull(encryptedKey, "encryptedKey must not be null");
		Assert.hasText(password, PASSWORD_MUST_NOT_BE_EMPTY);
		
		try
		{
			final byte[] decodeFromString = Base64Utils.decodeFromString(encryptedKey);
			final byte[] secret = decrypt(decodeFromString, password);
			return new SecretKeySpec(secret, 0, SHARED_KEY_SIZE, "AES");
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException ex)
		{
			throw new GeneralSecurityException("failed to decrypt shared key", ex);
		}
	}

	/**
	 * decodes an base64-encoded public key {@code com.ibm.websphere.ltpa.PublicKey}
	 *
	 * @param encryptedPublicKey the base64-encoded public key which corresponds to the private key that is used to sign an LTPA2 token
	 * @return the decoded public key
	 * @throws GeneralSecurityException if anything went wrong
	 */
	@NonNull
	public PublicKey decodePublicKey(@NonNull final String encryptedPublicKey) throws GeneralSecurityException
	{
		Assert.hasText(encryptedPublicKey, "encryptedPublicKey must not be empty");
		
		try
		{
			final byte[] parts = Base64Utils.decodeFromString(encryptedPublicKey);
			Assert.isTrue(parts.length == PUBLIC_MODULUS_LENGTH + PUBLIC_EXPONENT_LENGTH, "invalid encryptedPublicKey");
			final BigInteger modulus = new BigInteger(Arrays.copyOfRange(parts, 0, PUBLIC_MODULUS_LENGTH));
			final BigInteger exponent = new BigInteger(Arrays.copyOfRange(parts, PUBLIC_MODULUS_LENGTH, PUBLIC_MODULUS_LENGTH + PUBLIC_EXPONENT_LENGTH));
			final RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
			final KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(pubKeySpec);
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException ex)
		{
			throw new GeneralSecurityException("failed to decoded public key", ex);
		}
	}

	/**
	 * decrypt the private key ({@code com.ibm.websphere.ltpa.PrivateKey}) that is used to sign an LTPA2 token
	 *
	 * @param encryptedKey the base64-encoded and with 3DES encrypted key
	 * @param password the password for decryption
	 * @return the decrypted key
	 * @throws GeneralSecurityException if anything went wrong
	 */
	@NonNull
	public PrivateKey decryptPrivateKey(@NonNull final String encryptedKey, @NonNull final String password) throws GeneralSecurityException
	{
		Assert.hasText(encryptedKey, "encryptedKey must not be empty");
		Assert.hasText(password, PASSWORD_MUST_NOT_BE_EMPTY);
		
		try
		{
			final byte[] parts = decrypt(Base64Utils.decodeFromString(encryptedKey), password);

			// read the length of the field with the private exponent
			final int privateExponentLength = (new BigInteger(Arrays.copyOfRange(parts, 0, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH))).intValue();

			final BigInteger privateExponent = new BigInteger(Arrays.copyOfRange(parts, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength));
			final BigInteger p = new BigInteger(Arrays.copyOfRange(parts, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH + PRIVATE_P_Q_LENGTH));
			final BigInteger q = new BigInteger(Arrays.copyOfRange(parts, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH + PRIVATE_P_Q_LENGTH, PRIVATE_EXPONENT_LENGTH_FIELD_LENGTH + privateExponentLength + PUBLIC_EXPONENT_LENGTH + PRIVATE_P_Q_LENGTH + PRIVATE_P_Q_LENGTH));
			final BigInteger modulus = p.multiply(q);
			final RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
			final KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(privKeySpec);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | ArrayIndexOutOfBoundsException ex)
		{
			throw new GeneralSecurityException("failed to decrypt private key", ex);
		}
	}
}
