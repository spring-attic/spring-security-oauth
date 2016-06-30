/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.springframework.security.oauth2.provider.token.store;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.util.Assert;

/**
 * Helper that translates between JWT encoded token values and OAuth authentication
 * information (in both directions). Also acts as a {@link TokenEnhancer} when tokens are
 * granted.
 * 
 * @see TokenEnhancer
 * @see AccessTokenConverter
 * 
 * @author Dave Syer
 * @author Luke Taylor
 */
public class JwtAccessTokenConverter implements TokenEnhancer, AccessTokenConverter,
		InitializingBean {

	/**
	 * Field name for token id.
	 */
	public static final String TOKEN_ID = AccessTokenConverter.JTI;

	/**
	 * Field name for access token id.
	 */
	public static final String ACCESS_TOKEN_ID = AccessTokenConverter.ATI;

	private static final Log logger = LogFactory.getLog(JwtAccessTokenConverter.class);

	private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();

	private JsonParser objectMapper = JsonParserFactory.create();

	private String verifierKey = new RandomValueStringGenerator().generate();

	private Signer signer = new MacSigner(verifierKey);

	private String signingKey = verifierKey;

	private SignatureVerifier verifier;

	/**
	 * @param tokenConverter the tokenConverter to set
	 */
	public void setAccessTokenConverter(AccessTokenConverter tokenConverter) {
		this.tokenConverter = tokenConverter;
	}

	/**
	 * @return the tokenConverter in use
	 */
	public AccessTokenConverter getAccessTokenConverter() {
		return tokenConverter;
	}

	@Override
	public Map<String, ?> convertAccessToken(OAuth2AccessToken token,
			OAuth2Authentication authentication) {
		return tokenConverter.convertAccessToken(token, authentication);
	}

	@Override
	public OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map) {
		return tokenConverter.extractAccessToken(value, map);
	}

	@Override
	public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
		return tokenConverter.extractAuthentication(map);
	}

	/**
	 * Get the verification key for the token signatures.
	 * 
	 * @return the key used to verify tokens
	 */
	public Map<String, String> getKey() {
		Map<String, String> result = new LinkedHashMap<String, String>();
		result.put("alg", signer.algorithm());
		result.put("value", verifierKey);
		return result;
	}

	public void setKeyPair(KeyPair keyPair) {
		PrivateKey privateKey = keyPair.getPrivate();
		Assert.state(privateKey instanceof RSAPrivateKey, "KeyPair must be an RSA ");
		signer = new RsaSigner((RSAPrivateKey) privateKey);
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		verifier = new RsaVerifier(publicKey);
		verifierKey = "-----BEGIN PUBLIC KEY-----\n"
				+ new String(Base64.encode(publicKey.getEncoded()))
				+ "\n-----END PUBLIC KEY-----";
	}

	/**
	 * Sets the JWT signing key. It can be either a simple MAC key or an RSA key. RSA keys
	 * should be in OpenSSH format, as produced by <tt>ssh-keygen</tt>.
	 * 
	 * @param key the key to be used for signing JWTs.
	 */
	public void setSigningKey(String key) {
		Assert.hasText(key);
		key = key.trim();

		this.signingKey = key;

		if (isPublic(key)) {
			signer = new RsaSigner(key);
			logger.info("Configured with RSA signing key");
		}
		else {
			// Assume it's a MAC key
			this.verifierKey = key;
			signer = new MacSigner(key);
		}
	}

	/**
	 * @return true if the key has a public verifier
	 */
	private boolean isPublic(String key) {
		return key.startsWith("-----BEGIN");
	}

	/**
	 * @return true if the signing key is a public key
	 */
	public boolean isPublic() {
		return signer instanceof RsaSigner;
	}

	/**
	 * The key used for verifying signatures produced by this class. This is not used but
	 * is returned from the endpoint to allow resource servers to obtain the key.
	 * 
	 * For an HMAC key it will be the same value as the signing key and does not need to
	 * be set. For and RSA key, it should be set to the String representation of the
	 * public key, in a standard format (e.g. OpenSSH keys)
	 * 
	 * @param key the signature verification key (typically an RSA public key)
	 */
	public void setVerifierKey(String key) {
		this.verifierKey = key;
		try {
			new RsaSigner(verifierKey);
			throw new IllegalArgumentException(
					"Private key cannot be set as verifierKey property");
		}
		catch (Exception expected) {
			// Expected
		}
	}

	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
			OAuth2Authentication authentication) {
		DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
		Map<String, Object> info = new LinkedHashMap<String, Object>(
				accessToken.getAdditionalInformation());
		String tokenId = result.getValue();
		if (!info.containsKey(TOKEN_ID)) {
			info.put(TOKEN_ID, tokenId);
		}
		else {
			tokenId = (String) info.get(TOKEN_ID);
		}
		result.setAdditionalInformation(info);
		result.setValue(encode(result, authentication));
		OAuth2RefreshToken refreshToken = result.getRefreshToken();
		if (refreshToken != null) {
			DefaultOAuth2AccessToken encodedRefreshToken = new DefaultOAuth2AccessToken(
					accessToken);
			encodedRefreshToken.setValue(refreshToken.getValue());
			// Refresh tokens do not expire unless explicitly of the right type
			encodedRefreshToken.setExpiration(null);
			try {
				Map<String, Object> claims = objectMapper.parseMap(JwtHelper.decode(
						refreshToken.getValue()).getClaims());
				if (claims.containsKey(TOKEN_ID)) {
					encodedRefreshToken.setValue(claims.get(TOKEN_ID).toString());
				}
			}
			catch (IllegalArgumentException e) {
			}
			Map<String, Object> refreshTokenInfo = new LinkedHashMap<String, Object>(
					accessToken.getAdditionalInformation());
			refreshTokenInfo.put(TOKEN_ID, encodedRefreshToken.getValue());
			refreshTokenInfo.put(ACCESS_TOKEN_ID, tokenId);
			encodedRefreshToken.setAdditionalInformation(refreshTokenInfo);
			DefaultOAuth2RefreshToken token = new DefaultOAuth2RefreshToken(encode(
					encodedRefreshToken, authentication));
			if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
				Date expiration = ((ExpiringOAuth2RefreshToken) refreshToken)
						.getExpiration();
				encodedRefreshToken.setExpiration(expiration);
				token = new DefaultExpiringOAuth2RefreshToken(encode(encodedRefreshToken,
						authentication), expiration);
			}
			result.setRefreshToken(token);
		}
		return result;
	}

	public boolean isRefreshToken(OAuth2AccessToken token) {
		return token.getAdditionalInformation().containsKey(ACCESS_TOKEN_ID);
	}

	protected String encode(OAuth2AccessToken accessToken,
			OAuth2Authentication authentication) {
		String content;
		try {
			content = objectMapper.formatMap(tokenConverter.convertAccessToken(
					accessToken, authentication));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		String token = JwtHelper.encode(content, signer).getEncoded();
		return token;
	}

	protected Map<String, Object> decode(String token) {
		try {
			Jwt jwt = JwtHelper.decodeAndVerify(token, verifier);
			String content = jwt.getClaims();
			Map<String, Object> map = objectMapper.parseMap(content);
			if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
				Integer intValue = (Integer) map.get(EXP);
				map.put(EXP, new Long(intValue));
			}
			return map;
		}
		catch (Exception e) {
			throw new InvalidTokenException("Cannot convert access token to JSON", e);
		}
	}

	public void afterPropertiesSet() throws Exception {
		SignatureVerifier verifier = new MacSigner(verifierKey);
		try {
			verifier = new RsaVerifier(verifierKey);
		}
		catch (Exception e) {
			logger.warn("Unable to create an RSA verifier from verifierKey (ignoreable if using MAC)");
		}
		// Check the signing and verification keys match
		if (signer instanceof RsaSigner) {
			byte[] test = "test".getBytes();
			try {
				verifier.verify(test, signer.sign(test));
				logger.info("Signing and verification RSA keys match");
			}
			catch (InvalidSignatureException e) {
				logger.error("Signing and verification RSA keys do not match");
			}
		}
		else if (verifier instanceof MacSigner) {
			// Avoid a race condition where setters are called in the wrong order. Use of
			// == is intentional.
			Assert.state(
					this.signingKey == this.verifierKey,
					"For MAC signing you do not need to specify the verifier key separately, and if you do it must match the signing key");
		}
		this.verifier = verifier;
	}

}
