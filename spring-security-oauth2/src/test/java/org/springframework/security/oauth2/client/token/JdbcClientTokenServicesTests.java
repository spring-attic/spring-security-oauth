package org.springframework.security.oauth2.client.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

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

/**
 * @author Dave Syer
 * 
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

}
