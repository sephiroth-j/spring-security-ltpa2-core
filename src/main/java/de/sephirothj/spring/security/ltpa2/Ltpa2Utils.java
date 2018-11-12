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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.LocalDateTime;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import lombok.experimental.UtilityClass;
import org.springframework.lang.NonNull;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;

/**
 * Utility class for operations on an LTPA2 token
 *
 * @author Sephiroth
 */
@UtilityClass
public class Ltpa2Utils
{
	private static final String TOKEN_ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String SIGNATURE_ALGORITM = "SHA1withRSA";
	private static final String SIGNATURE_DIGEST_METHOD = "SHA";
	private static final String TOKEN_MUST_NOT_BE_EMPTY = "token must not be empty";
	private static final String KEY_MUST_NOT_BE_NULL = "key must not be null";
	private static final String TOKEN_IS_MALFORMED = "token is malformed";

	/**
	 * decrypts an base64-encoded LTPA2 token
	 *
	 * @param encryptedToken the base64-encoded and encrypted token
	 * @param key the shared secret key that was used to encrypt {@code encryptedToken}
	 * @return the serialized token
	 * @throws InvalidLtpa2TokenException in case something went wrong
	 */
	@NonNull
	String decryptLtpa2Token(@NonNull final String encryptedToken, @NonNull final SecretKey key) throws InvalidLtpa2TokenException
	{
		Assert.hasText(encryptedToken, "encryptedToken must not be empty");
		Assert.notNull(key, KEY_MUST_NOT_BE_NULL);
		
		try
		{
			final byte[] rawToken = Base64Utils.decodeFromString(encryptedToken);
			final Cipher c = Cipher.getInstance(TOKEN_ENCRYPTION_ALGORITHM);
			final IvParameterSpec iv = new IvParameterSpec(key.getEncoded());
			c.init(Cipher.DECRYPT_MODE, key, iv);
			final byte[] rawDecodedToken = c.doFinal(rawToken);
			return new String(rawDecodedToken, StandardCharsets.UTF_8);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalArgumentException ex)
		{
			throw new InvalidLtpa2TokenException("failed to decrypt LTPA2 token", ex);
		}
	}

	/**
	 * returns the three parts of the given LTPA2 token
	 *
	 * @param token a serialized LTPA2 token (unencrypted)
	 * @return Array with length 3. Index 0 = Body, 1 = expires and 2 = base64-encoded signature
	 * @throws IllegalArgumentException if the token is empty
	 * @throws IllegalArgumentException if the token is malformed
	 */
	private String[] getTokenParts(@NonNull final String token) throws IllegalArgumentException
	{
		Assert.hasText(token, TOKEN_MUST_NOT_BE_EMPTY);
		Assert.hasText(token, "serializedToken must not be empty");
		
		final String[] tokenParts = token.split("\\%", 3);
		Assert.notEmpty(tokenParts, "invalid serialized LTPA2 token. token must contain exactly three '%'!");
		Assert.isTrue(tokenParts.length == 3, "invalid serialized LTPA2 token. token must contain exactly three '%'!");
		return tokenParts;
	}

	/**
	 * create a new instance of {@linkplain Ltpa2Token} from the given serialized LTPA2 token
	 *
	 * @param tokenStr a serialized LTPA2 token (unencrypted)
	 * @return instance of {@linkplain Ltpa2Token}
	 * @throws InvalidLtpa2TokenException if the token is malformed
	 */
	@NonNull
	Ltpa2Token makeInstance(@NonNull final String tokenStr) throws InvalidLtpa2TokenException
	{
		Assert.hasText(tokenStr, "tokenStr must not be empty");
		
		try
		{
			final String[] tokenParts = getTokenParts(tokenStr);
			final Ltpa2Token token = Ltpa2Token.of(tokenParts[0]);
			if (token.getExpire() == null)
			{
				token.setExpire(tokenParts[1]);
			}
			return token;
		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidLtpa2TokenException(TOKEN_IS_MALFORMED);
		}
	}

	/**
	 * checks if the given token is expired
	 *
	 * @param token a serialized LTPA2 token (unencrypted)
	 * @return whether the given token is expired or not
	 * @throws InvalidLtpa2TokenException if the token is malformed
	 */
	boolean isTokenExpired(@NonNull final String token) throws InvalidLtpa2TokenException
	{
		Assert.hasText(token, TOKEN_MUST_NOT_BE_EMPTY);
		
		try
		{
			final Ltpa2Token instance = makeInstance(token);
			return isTokenExpired(instance);
		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidLtpa2TokenException(TOKEN_IS_MALFORMED);
		}
	}

	/**
	 * checks if the given token is expired
	 *
	 * @param token a LTPA2 token instance
	 * @return whether the given token is expired or not
	 */
	boolean isTokenExpired(@NonNull final Ltpa2Token token)
	{
		Assert.notNull(token, "token must not be null");
		
		final LocalDateTime expires = token.getExpire();
		return expires.isBefore(LocalDateTime.now());
	}

	/**
	 * checks if the signature of the given token is valid
	 *
	 * @param token a serialized LTPA2 token (unencrypted)
	 * @param signerKey the base64-encoded public key which corresponds to the private key that was used to sign an LTPA2 token
	 * @return whether the signature for the given token is valid or not
	 * @throws InvalidLtpa2TokenException in case something went wrong when decoding {@code signerKey}
	 * @throws InvalidLtpa2TokenException if the token is malformed
	 * @throws InvalidLtpa2TokenException in case an error occured during signature verification
	 * @see LtpaKeyUtils#decodePublicKey(java.lang.String)
	 * @see #isSignatureValid(java.lang.String, java.security.PublicKey)
	 */
	boolean isSignatureValid(@NonNull final String token, @NonNull final String signerKey) throws InvalidLtpa2TokenException
	{
		Assert.hasText(token, TOKEN_MUST_NOT_BE_EMPTY);
		Assert.hasText(signerKey, "signerKey must not be empty");
		
		try
		{
			return isSignatureValid(token, LtpaKeyUtils.decodePublicKey(signerKey));
		}
		catch (GeneralSecurityException ex)
		{
			throw new InvalidLtpa2TokenException("invalid public key", ex);
		}
	}

	/**
	 * checks if the signature of the given token is valid
	 *
	 * @param token a serialized LTPA2 token (unencrypted)
	 * @param signerKey the public key which corresponds to the private key that was used to sign an LTPA2 token
	 * @return whether the signature for the given token is valid or not
	 * @throws InvalidLtpa2TokenException in case an error occured during signature verification
	 * @throws InvalidLtpa2TokenException if the token is malformed
	 */
	boolean isSignatureValid(@NonNull final String token, @NonNull final PublicKey signerKey) throws InvalidLtpa2TokenException
	{
		Assert.hasText(token, TOKEN_MUST_NOT_BE_EMPTY);
		Assert.notNull(signerKey, "signerKey must not be null");
		
		try
		{
			final String[] tokenParts = getTokenParts(token);
			final Signature signer = Signature.getInstance(SIGNATURE_ALGORITM);
			signer.initVerify(signerKey);
			final MessageDigest md = MessageDigest.getInstance(SIGNATURE_DIGEST_METHOD);
			final byte[] bodyHash = md.digest(tokenParts[0].getBytes());
			signer.update(bodyHash);
			return signer.verify(Base64Utils.decodeFromString(tokenParts[2]));
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex)
		{
			throw new InvalidLtpa2TokenException("failed to verify token signature", ex);
		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidLtpa2TokenException(TOKEN_IS_MALFORMED);
		}
	}

	/**
	 * signs the given LTPA2 token
	 *
	 * @param token a serialized LTPA2 token (unencrypted)
	 * @param key the private key for signing the given token
	 * @return the base64-encoded signature of the token
	 * @throws InvalidLtpa2TokenException in case an error occured during signature creation
	 * @see Ltpa2Token#toString()
	 */
	@NonNull
	String signToken(@NonNull final String token, @NonNull final PrivateKey key) throws InvalidLtpa2TokenException
	{
		Assert.hasText(token, TOKEN_MUST_NOT_BE_EMPTY);
		Assert.notNull(key, KEY_MUST_NOT_BE_NULL);
		
		try
		{
			final Signature signer = Signature.getInstance(SIGNATURE_ALGORITM);
			signer.initSign(key);
			final MessageDigest md = MessageDigest.getInstance(SIGNATURE_DIGEST_METHOD);
			final byte[] bodyHash = md.digest(token.getBytes());
			signer.update(bodyHash);
			return Base64Utils.encodeToString(signer.sign());
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException ex)
		{
			throw new InvalidLtpa2TokenException("failed to sign token", ex);
		}
	}

	/**
	 * create a serialized, signed and encrypted LTPA2 token
	 *
	 * @param token the token
	 * @param signerKey the private key for signing the given token
	 * @param key the shared secret key for encrypting the given token
	 * @return serialized, signed and encrypted LTPA2 token
	 * @throws InvalidLtpa2TokenException in case an error occured during signature creation
	 * @throws InvalidLtpa2TokenException in case an error occured during encrypting the token
	 */
	@NonNull
	public String encryptToken(@NonNull final Ltpa2Token token, @NonNull final PrivateKey signerKey, @NonNull final SecretKey key) throws InvalidLtpa2TokenException
	{
		Assert.notNull(token, "token must not be null");
		Assert.notNull(signerKey, "signerKey must not be null");
		Assert.notNull(key, KEY_MUST_NOT_BE_NULL);
		
		final String serializedToken = token.toString();
		final String signature = signToken(serializedToken, signerKey);
		final StringBuilder rawTokenStr = new StringBuilder(serializedToken);
		rawTokenStr.append('%').append(token.getAttribute(Ltpa2Token.EXPIRE_ATTRIBUTE_NAME)).append('%').append(signature);
		try
		{
			final Cipher c = Cipher.getInstance(TOKEN_ENCRYPTION_ALGORITHM);
			final IvParameterSpec iv = new IvParameterSpec(key.getEncoded());
			c.init(Cipher.ENCRYPT_MODE, key, iv);
			final byte[] rawEncryptedToken = c.doFinal(rawTokenStr.toString().getBytes(StandardCharsets.UTF_8));
			return Base64Utils.encodeToString(rawEncryptedToken);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidAlgorithmParameterException ex)
		{
			throw new InvalidLtpa2TokenException("failed to encrypt token", ex);
		}
	}
}
