package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;

public class TestJdbcClientDetailsService {
	private JdbcClientDetailsService service;
	private JdbcTemplate jdbcTemplate;
	private EmbeddedDatabase db;

	private static final String INSERT_SQL = "insert into oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities) values (?, ?, ?, ?, ?, ?, ?)";

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

	@Test
	public void testLoadingClientForNonExsitingClientId() {
		try {
			service.loadClientByClientId("nonExistingClientId");
			fail("Should have thrown exception");
		} catch (InvalidClientException e) {
			// valid
		}
	}

	@Test
	public void testLoadingClientIdWithNoDetails() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithNoDetails", null, null, null, null, null, null);

		ClientDetails clientDetails = service.loadClientByClientId("clientIdWithNoDetails");

		assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
		assertFalse(clientDetails.isSecretRequired());
		assertNull(clientDetails.getClientSecret());
		assertFalse(clientDetails.isScoped());
		assertEquals(0, clientDetails.getScope().size());
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		assertNull(clientDetails.getWebServerRedirectUri());
		assertEquals(0, clientDetails.getAuthorities().size());
	}

	@Test
	public void testLoadingClientIdWithSingleDetails() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithSingleDetails", "myResource", "mySecret", "myScope", "myAuthorizedGrantType",
				"myRedirectUri", "myAuthority");

		ClientDetails clientDetails = service.loadClientByClientId("clientIdWithSingleDetails");

		assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(1, clientDetails.getScope().size());
		assertEquals("myScope", clientDetails.getScope().get(0));
		assertEquals(1, clientDetails.getResourceIds().size());
		assertEquals("myResource", clientDetails.getResourceIds().get(0));
		assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals("myAuthorizedGrantType", clientDetails.getAuthorizedGrantTypes().get(0));
		assertEquals("myRedirectUri", clientDetails.getWebServerRedirectUri());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals("myAuthority", clientDetails.getAuthorities().get(0).getAuthority());
	}

	@Test
	public void testLoadingClientIdWithMultipleDetails() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithMultipleDetails", "myResource1,myResource2", "mySecret", "myScope1,myScope2",
				"myAuthorizedGrantType1,myAuthorizedGrantType2", "myRedirectUri", "myAuthority1,myAuthority2");

		ClientDetails clientDetails = service.loadClientByClientId("clientIdWithMultipleDetails");

		assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(2, clientDetails.getResourceIds().size());
		assertEquals("myResource1", clientDetails.getResourceIds().get(0));
		assertEquals("myResource2", clientDetails.getResourceIds().get(1));
		assertEquals(2, clientDetails.getScope().size());
		assertEquals("myScope1", clientDetails.getScope().get(0));
		assertEquals("myScope2", clientDetails.getScope().get(1));
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals("myAuthorizedGrantType1", clientDetails.getAuthorizedGrantTypes().get(0));
		assertEquals("myAuthorizedGrantType2", clientDetails.getAuthorizedGrantTypes().get(1));
		assertEquals("myRedirectUri", clientDetails.getWebServerRedirectUri());
		assertEquals(2, clientDetails.getAuthorities().size());
		assertEquals("myAuthority1", clientDetails.getAuthorities().get(0).getAuthority());
		assertEquals("myAuthority2", clientDetails.getAuthorities().get(1).getAuthority());
	}
}
