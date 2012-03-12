package org.springframework.security.oauth2.provider;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;

import java.util.Iterator;

import static org.junit.Assert.*;

public class TestJdbcClientDetailsService {
	private JdbcClientDetailsService service;

	private JdbcTemplate jdbcTemplate;

	private EmbeddedDatabase db;

	private static final String INSERT_CLIENT_SQL = "insert into oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types, authorities, access_token_validity) values (?, ?, ?, ?, ?, ?, ?)";

	private static final String INSERT_REDIRECT_SQL = "insert into oauth_client_redirect_uri (client_id, web_server_redirect_uri) values (?, ?)";


	private static final String CUSTOM_CLIENT_INSERT_SQL = "insert into ClientDetails (appId, resourceIds, appSecret, scope, grantTypes, authorities) values (?, ?, ?, ?, ?, ?)";
	private static final String CUSTOM_INSERT_REDIRECT_SQL = "insert into RedirectUri (appId, redirectUri) values (?, ?)";

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		jdbcTemplate = new JdbcTemplate(db);
		service = new JdbcClientDetailsService(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	@Test ( expected = InvalidClientException.class )
	public void testLoadingClientForNonExistingClientId() {
		service.loadClientByClientId("nonExistingClientId");
	}

	@Test
	public void testLoadingClientIdWithNoDetails() {
		jdbcTemplate.update(INSERT_CLIENT_SQL, "clientIdWithNoDetails", null, null, null, null, null, null);
		ClientDetails clientDetails = service.loadClientByClientId("clientIdWithNoDetails");

		assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
		assertFalse(clientDetails.isSecretRequired());
		assertNull(clientDetails.getClientSecret());
		assertFalse(clientDetails.isScoped());
		assertEquals(0, clientDetails.getScope().size());
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		assertNull(clientDetails.getRegisteredRedirectUri());
		assertEquals(0, clientDetails.getAuthorities().size());
		assertEquals(0, clientDetails.getAccessTokenValiditySeconds());
	}

	@Test
	public void testLoadingClientIdWithSingleDetails() {
		jdbcTemplate.update(INSERT_CLIENT_SQL, "clientIdWithSingleDetails", "myResource", "mySecret", "myScope",
							"myAuthorizedGrantType", "myAuthority", 100);
		jdbcTemplate.update(INSERT_REDIRECT_SQL, "clientIdWithSingleDetails", "myRedirectUri");

		ClientDetails clientDetails = service.loadClientByClientId("clientIdWithSingleDetails");

		assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(1, clientDetails.getScope().size());
		assertEquals("myScope", clientDetails.getScope().iterator().next());
		assertEquals(1, clientDetails.getResourceIds().size());
		assertEquals("myResource", clientDetails.getResourceIds().iterator().next());
		assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals("myAuthorizedGrantType", clientDetails.getAuthorizedGrantTypes().iterator().next());
		assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri().iterator().next());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals("myAuthority", clientDetails.getAuthorities().iterator().next().getAuthority());
		assertEquals(100, clientDetails.getAccessTokenValiditySeconds());
	}

	@Test
	public void testLoadingClientIdWithSingleDetailsInCustomTable() {
		jdbcTemplate.update(CUSTOM_CLIENT_INSERT_SQL, "clientIdWithSingleDetails", "myResource", "mySecret", "myScope", "myAuthorizedGrantType", "myAuthority");
		jdbcTemplate.update(CUSTOM_INSERT_REDIRECT_SQL, "clientIdWithSingleDetails", "myRedirectUri");

		JdbcClientDetailsService customService = new JdbcClientDetailsService(db);
		customService.setSelectClientDetailsSql("select appId, resourceIds, appSecret, scope, "
														+ "grantTypes, authorities, access_token_validity from ClientDetails where appId = ?");
		customService.setSelectClientRedirectUrisSql("select redirectUri from RedirectUri where appId = ?");

		ClientDetails clientDetails = customService.loadClientByClientId("clientIdWithSingleDetails");

		assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(1, clientDetails.getScope().size());
		assertEquals("myScope", clientDetails.getScope().iterator().next());
		assertEquals(1, clientDetails.getResourceIds().size());
		assertEquals("myResource", clientDetails.getResourceIds().iterator().next());
		assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals("myAuthorizedGrantType", clientDetails.getAuthorizedGrantTypes().iterator().next());
		assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri().iterator().next());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals("myAuthority", clientDetails.getAuthorities().iterator().next().getAuthority());
	}

	@Test
	public void testLoadingClientIdWithMultipleDetails() {
		jdbcTemplate.update(INSERT_CLIENT_SQL, "clientIdWithMultipleDetails", "myResource1,myResource2", "mySecret",
							"myScope1,myScope2", "myAuthorizedGrantType1,myAuthorizedGrantType2", "myAuthority1,myAuthority2", 100);
		jdbcTemplate.update(INSERT_REDIRECT_SQL, "clientIdWithMultipleDetails", "myRedirectUri");

		ClientDetails clientDetails = service.loadClientByClientId("clientIdWithMultipleDetails");

		assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(2, clientDetails.getResourceIds().size());
		Iterator<String> resourceIds = clientDetails.getResourceIds().iterator();
		assertEquals("myResource1", resourceIds.next());
		assertEquals("myResource2", resourceIds.next());
		assertEquals(2, clientDetails.getScope().size());
		Iterator<String> scope = clientDetails.getScope().iterator();
		assertEquals("myScope1", scope.next());
		assertEquals("myScope2", scope.next());
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		Iterator<String> grantTypes = clientDetails.getAuthorizedGrantTypes().iterator();
		assertEquals("myAuthorizedGrantType1", grantTypes.next());
		assertEquals("myAuthorizedGrantType2", grantTypes.next());
		assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri().iterator().next());
		assertEquals(2, clientDetails.getAuthorities().size());
		Iterator<GrantedAuthority> authorities = clientDetails.getAuthorities().iterator();
		assertEquals("myAuthority1", authorities.next().getAuthority());
		assertEquals("myAuthority2", authorities.next().getAuthority());
		assertEquals(100, clientDetails.getAccessTokenValiditySeconds());
	}
}
