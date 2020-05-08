package org.springframework.security.oauth2.client.token;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.company.oauth2.CustomOAuth2AccessToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.SerializationStrategy;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.common.util.WhitelistedSerializationStrategy;

import static org.junit.Assert.*;

/**
 * @author Dave Syer
 * @author Artem Smotrakov
 */
public class JdbcClientTokenServicesTests {

	private JdbcClientTokenServices tokenStore;

	private EmbeddedDatabase db;

	public JdbcClientTokenServices getTokenServices() {
		return tokenStore;
	}

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		tokenStore = new JdbcClientTokenServices(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	@Test
	public void testSaveAndRetrieveToken() throws Exception {
		OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		Authentication authentication = new UsernamePasswordAuthenticationToken("marissa", "koala");
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		resource.setScope(Arrays.asList("foo", "bar"));
		tokenStore.saveAccessToken(resource, authentication, accessToken);
		OAuth2AccessToken result = tokenStore.getAccessToken(resource, authentication);
		assertEquals(accessToken, result);
	}

	@Test
	public void testSaveAndRetrieveTokenForClientCredentials() throws Exception {
		OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		resource.setScope(Arrays.asList("foo", "bar"));
		tokenStore.saveAccessToken(resource, null, accessToken);
		OAuth2AccessToken result = tokenStore.getAccessToken(resource, null);
		assertEquals(accessToken, result);
	}

	@Test
	public void testSaveAndRemoveToken() throws Exception {
		OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		Authentication authentication = new UsernamePasswordAuthenticationToken("marissa", "koala");
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		resource.setScope(Arrays.asList("foo", "bar"));
		tokenStore.saveAccessToken(resource, authentication, accessToken);
		tokenStore.removeAccessToken(resource, authentication);
		// System.err.println(new JdbcTemplate(db).queryForList("select * from oauth_client_token"));
		OAuth2AccessToken result = tokenStore.getAccessToken(resource, authentication);
		assertNull(result);
	}

	@Test
	public void testSaveAndRetrieveCustomToken() {
		OAuth2AccessToken accessToken = new CustomOAuth2AccessToken("FOO");
		Authentication authentication = new UsernamePasswordAuthenticationToken("marissa", "koala");
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		resource.setScope(Arrays.asList("foo", "bar"));
		tokenStore.saveAccessToken(resource, authentication, accessToken);
		OAuth2AccessToken result = tokenStore.getAccessToken(resource, authentication);
		assertNotNull(result);
		assertEquals(accessToken, result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSaveAndRetrieveNotAllowedCustomToken() {
		OAuth2AccessToken accessToken = new CustomOAuth2AccessToken("FOO");
		Authentication authentication = new UsernamePasswordAuthenticationToken("marissa", "koala");
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		resource.setScope(Arrays.asList("foo", "bar"));
		WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy();
		SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
		try {
			SerializationUtils.setSerializationStrategy(newStrategy);
			tokenStore.saveAccessToken(resource, authentication, accessToken);
			tokenStore.getAccessToken(resource, authentication);
		} finally {
			SerializationUtils.setSerializationStrategy(oldStrategy);
		}
	}

	@Test
	public void testSaveAndRetrieveCustomTokenWithCustomSerializationStrategy() {
		List<String> allowedClasses = new ArrayList<String>();
		allowedClasses.add("java.util.");
		allowedClasses.add("org.springframework.security.");
		allowedClasses.add("org.company.oauth2.CustomOAuth2AccessToken");
		WhitelistedSerializationStrategy newStrategy = new WhitelistedSerializationStrategy(allowedClasses);
		SerializationStrategy oldStrategy = SerializationUtils.getSerializationStrategy();
		try {
			SerializationUtils.setSerializationStrategy(newStrategy);
			OAuth2AccessToken accessToken = new CustomOAuth2AccessToken("FOO");
			Authentication authentication = new UsernamePasswordAuthenticationToken("marissa", "koala");
			AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
			resource.setClientId("client");
			resource.setScope(Arrays.asList("foo", "bar"));
			tokenStore.saveAccessToken(resource, authentication, accessToken);
			OAuth2AccessToken result = tokenStore.getAccessToken(resource, authentication);
			assertNotNull(result);
			assertEquals(accessToken, result);
		} finally {
			SerializationUtils.setSerializationStrategy(oldStrategy);
		}
	}
}
