/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.springframework.security.oauth2.provider.token.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class JwtAccessTokenConverterTests {

	private JwtAccessTokenConverter tokenEnhancer;

	private Authentication userAuthentication;

	@Before
	public void setUp() throws Exception {
		tokenEnhancer = new JwtAccessTokenConverter();
		userAuthentication = new TestAuthentication("test2", true);
	}

	@Test
	public void testEnhanceAccessToken() {
		OAuth2Authentication authentication = new OAuth2Authentication(
				createOAuth2Request("foo", null), userAuthentication);
		OAuth2AccessToken token = tokenEnhancer.enhance(new DefaultOAuth2AccessToken(
				"FOO"), authentication);
		assertNotNull(token.getValue());
		assertEquals("FOO", token.getAdditionalInformation()
				.get(AccessTokenConverter.JTI));
		String claims = JwtHelper.decode(token.getValue()).getClaims();
		assertTrue("Wrong claims: " + claims,
				claims.contains("\"" + AccessTokenConverter.JTI + "\":\"FOO\""));
		assertTrue("Wrong claims: " + claims,
				claims.contains("\"" + UserAuthenticationConverter.USERNAME + "\""));
	}

	@Test
	public void testScopePreserved() {
		OAuth2Authentication authentication = new OAuth2Authentication(
				createOAuth2Request("foo", Collections.singleton("read")),
				userAuthentication);
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
		original.setScope(authentication.getOAuth2Request().getScope());
		OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
		assertNotNull(token.getValue());
		assertEquals(Collections.singleton("read"), token.getScope());
	}

	@Test
	public void testRefreshTokenAdded() throws Exception {
		OAuth2Authentication authentication = new OAuth2Authentication(
				createOAuth2Request("foo", Collections.singleton("read")),
				userAuthentication);
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
		original.setScope(authentication.getOAuth2Request().getScope());
		original.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
		original.setExpiration(new Date());
		OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
		assertNotNull(token.getValue());
		assertNotNull(token.getRefreshToken());
		JsonParser parser = JsonParserFactory.create();
		Map<String, Object> claims = parser.parseMap(JwtHelper.decode(
				token.getRefreshToken().getValue()).getClaims());
		assertEquals(Arrays.asList("read"), claims.get(AccessTokenConverter.SCOPE));
		assertEquals("FOO", claims.get(AccessTokenConverter.ATI));
		assertEquals("BAR", claims.get(AccessTokenConverter.JTI));
		assertNull(claims.get(AccessTokenConverter.EXP));
		tokenEnhancer.afterPropertiesSet();
		assertTrue(tokenEnhancer.isRefreshToken(tokenEnhancer.extractAccessToken(token
				.getRefreshToken().getValue(), tokenEnhancer.decode(token
				.getRefreshToken().getValue()))));
	}

	@Test
	public void testExpiringRefreshTokenAdded() throws Exception {
		OAuth2Authentication authentication = new OAuth2Authentication(
				createOAuth2Request("foo", Collections.singleton("read")),
				userAuthentication);
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
		original.setScope(authentication.getOAuth2Request().getScope());
		original.setRefreshToken(new DefaultExpiringOAuth2RefreshToken("BAR", new Date(0)));
		original.setExpiration(new Date());
		OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
		assertNotNull(token.getValue());
		assertNotNull(token.getRefreshToken());
		JsonParser parser = JsonParserFactory.create();
		Map<String, Object> claims = parser.parseMap(JwtHelper.decode(
				token.getRefreshToken().getValue()).getClaims());
		assertEquals(Arrays.asList("read"), claims.get(AccessTokenConverter.SCOPE));
		assertEquals("FOO", claims.get(AccessTokenConverter.ATI));
		assertEquals("BAR", claims.get(AccessTokenConverter.JTI));
		assertEquals(0, claims.get(AccessTokenConverter.EXP));
		tokenEnhancer.afterPropertiesSet();
		assertTrue(tokenEnhancer.isRefreshToken(tokenEnhancer.extractAccessToken(token
				.getRefreshToken().getValue(), tokenEnhancer.decode(token
				.getRefreshToken().getValue()))));
	}

	@Test
	public void testRefreshTokenAccessTokenIdWhenDoubleEnhanced() throws Exception {
		OAuth2Authentication authentication = new OAuth2Authentication(
				createOAuth2Request("foo", Collections.singleton("read")),
				userAuthentication);
		DefaultOAuth2AccessToken original = new DefaultOAuth2AccessToken("FOO");
		original.setScope(authentication.getOAuth2Request().getScope());
		original.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
		OAuth2AccessToken token = tokenEnhancer.enhance(original, authentication);
		token = tokenEnhancer.enhance(token, authentication);
		assertNotNull(token.getValue());
		assertNotNull(token.getRefreshToken());
		JsonParser parser = JsonParserFactory.create();
		Map<String, Object> claims = parser.parseMap(JwtHelper.decode(
				token.getRefreshToken().getValue()).getClaims());
		assertEquals(Arrays.asList("read"), claims.get(AccessTokenConverter.SCOPE));
		assertEquals("FOO", claims.get(AccessTokenConverter.ATI));
		assertEquals("Wrong claims: " + claims, "BAR", claims.get(AccessTokenConverter.JTI));
	}

	@Test
	public void rsaKeyCreatesValidRsaSignedTokens() throws Exception {
		String rsaKey = "-----BEGIN RSA PRIVATE KEY-----  \n"
				+ "MIIBywIBAAJhAOTeb4AZ+NwOtPh+ynIgGqa6UWNVe6JyJi+loPmPZdpHtzoqubnC \n"
				+ "wEs6JSiSZ3rButEAw8ymgLV6iBY02hdjsl3h5Z0NWaxx8dzMZfXe4EpfB04ISoqq\n"
				+ "hZCxchvuSDP4eQIDAQABAmEAqUuYsuuDWFRQrZgsbGsvC7G6zn3HLIy/jnM4NiJK\n"
				+ "t0JhWNeN9skGsR7bqb1Sak2uWqW8ZqnqgAC32gxFRYHTavJEk6LTaHWovwDEhPqc\n"
				+ "Zs+vXd6tZojJQ35chR/slUEBAjEA/sAd1oFLWb6PHkaz7r2NllwUBTvXL4VcMWTS\n"
				+ "pN+5cU41i9fsZcHw6yZEl+ZCicDxAjEA5f3R+Bj42htNI7eylebew1+sUnFv1xT8\n"
				+ "jlzxSzwVkoZo+vef7OD6OcFLeInAHzAJAjEAs6izolK+3ETa1CRSwz0lPHQlnmdM\n"
				+ "Y/QuR5tuPt6U/saEVuJpkn4LNRtg5qt6I4JRAjAgFRYTG7irBB/wmZFp47izXEc3\n"
				+ "gOdvA1hvq3tlWU5REDrYt24xpviA0fvrJpwMPbECMAKDKdiDi6Q4/iBkkzNMefA8\n"
				+ "7HX27b9LR33don/1u/yvzMUo+lrRdKAFJ+9GPE9XFA== \n"
				+ "-----END RSA PRIVATE KEY----- ";
		tokenEnhancer.setSigningKey(rsaKey);
		OAuth2Authentication authentication = new OAuth2Authentication(
				createOAuth2Request("foo", null), userAuthentication);
		OAuth2AccessToken token = tokenEnhancer.enhance(new DefaultOAuth2AccessToken(
				"FOO"), authentication);
		JwtHelper.decodeAndVerify(token.getValue(), new RsaVerifier(rsaKey));
	}

	@Test
	public void publicKeyStringIsReturnedFromTokenKeyEndpoint() throws Exception {
		tokenEnhancer.setVerifierKey("-----BEGIN RSA PUBLIC KEY-----\n"
				+ "MGgCYQDk3m+AGfjcDrT4fspyIBqmulFjVXuiciYvpaD5j2XaR7c6Krm5wsBLOiUo\n"
				+ "kmd6wbrRAMPMpoC1eogWNNoXY7Jd4eWdDVmscfHczGX13uBKXwdOCEqKqoWQsXIb\n"
				+ "7kgz+HkCAwEAAQ==\n" + "-----END RSA PUBLIC KEY-----");
		tokenEnhancer.afterPropertiesSet();
		Map<String, String> key = tokenEnhancer.getKey();
		assertTrue("Wrong key: " + key, key.get("value").contains("-----BEGIN"));
	}

	@Test
	public void publicKeyStringIsReturnedFromTokenKeyEndpointWithNullPrincipal()
			throws Exception {
		tokenEnhancer.setVerifierKey("-----BEGIN RSA PUBLIC KEY-----\n"
				+ "MGgCYQDk3m+AGfjcDrT4fspyIBqmulFjVXuiciYvpaD5j2XaR7c6Krm5wsBLOiUo\n"
				+ "kmd6wbrRAMPMpoC1eogWNNoXY7Jd4eWdDVmscfHczGX13uBKXwdOCEqKqoWQsXIb\n"
				+ "7kgz+HkCAwEAAQ==\n" + "-----END RSA PUBLIC KEY-----");
		Map<String, String> key = tokenEnhancer.getKey();
		assertTrue("Wrong key: " + key, key.get("value").contains("-----BEGIN"));
	}

	@Test
	public void sharedSecretIsReturnedFromTokenKeyEndpoint() throws Exception {
		tokenEnhancer.setVerifierKey("someKey");
		assertEquals("{alg=HMACSHA256, value=someKey}", tokenEnhancer.getKey().toString());
	}

	@Test(expected = IllegalStateException.class)
	public void keysNotMatchingWithMacSigner() throws Exception {
		tokenEnhancer.setSigningKey("aKey");
		tokenEnhancer.setVerifierKey("someKey");
		tokenEnhancer.afterPropertiesSet();
	}

	@Test
	public void rsaKeyPair() throws Exception {
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(new ClassPathResource(
				"keystore.jks"), "foobar".toCharArray());
		KeyPair keys = factory.getKeyPair("test");
		tokenEnhancer.setKeyPair(keys);
		tokenEnhancer.afterPropertiesSet();
		assertTrue(tokenEnhancer.getKey().get("value").contains("BEGIN PUBLIC"));
	}

	@Test
	public void publicKeyOnlyAllowedForVerification() throws Exception {
		tokenEnhancer.setVerifierKey("-----BEGIN RSA PUBLIC KEY-----\n"
				+ "MGgCYQDk3m+AGfjcDrT4fspyIBqmulFjVXuiciYvpaD5j2XaR7c6Krm5wsBLOiUo\n"
				+ "kmd6wbrRAMPMpoC1eogWNNoXY7Jd4eWdDVmscfHczGX13uBKXwdOCEqKqoWQsXIb\n"
				+ "7kgz+HkCAwEAAQ==\n" + "-----END RSA PUBLIC KEY-----");
		tokenEnhancer.afterPropertiesSet();
		tokenEnhancer
				.decode("eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyX25hbWUiOiJ0ZXN0MiIsImp0aSI6IkZPTyIsImNsaWVudF9pZCI6ImZvbyJ9.b43ob1ALSIwr_J2oEnfMhsXvYkr1qVBNhigNH2zlaE1OQLhLfT-DMlFtHcyUlyap0C2n0q61SPaGE_z715TV0uTAv2YKDN4fKZz2bMR7eHLsvaaCuvs7KCOi_aSROaUG");
		Map<String, String> key = tokenEnhancer.getKey();
		assertTrue("Wrong key: " + key, key.get("value").contains("-----BEGIN"));
	}

	private OAuth2Request createOAuth2Request(String clientId, Set<String> scope) {
		return new OAuth2Request(Collections.<String, String> emptyMap(), clientId, null,
				true, scope, null, null, null, null);
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;

		private String principal;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getPrincipal() {
			return this.principal;
		}
	}

}
