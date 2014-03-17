package org.springframework.security.oauth2.provider.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

public class JdbcClientDetailsServiceTests {
	private JdbcClientDetailsService service;

	private JdbcTemplate jdbcTemplate;

	private EmbeddedDatabase db;

	private static final String SELECT_SQL = "select client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity from oauth_client_details where client_id=?";

	private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, autoapprove) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private static final String CUSTOM_INSERT_SQL = "insert into ClientDetails (appId, appSecret, resourceIds, scope, grantTypes, redirectUrl, authorities) values (?, ?, ?, ?, ?, ?, ?)";

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts
		// classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		jdbcTemplate = new JdbcTemplate(db);
		service = new JdbcClientDetailsService(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	@Test(expected = NoSuchClientException.class)
	public void testLoadingClientForNonExistingClientId() {
		service.loadClientByClientId("nonExistingClientId");
	}

	@Test
	public void testLoadingClientIdWithNoDetails() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithNoDetails", null, null,
				null, null, null, null, null, null, null);

		ClientDetails clientDetails = service
				.loadClientByClientId("clientIdWithNoDetails");

		assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
		assertFalse(clientDetails.isSecretRequired());
		assertNull(clientDetails.getClientSecret());
		assertFalse(clientDetails.isScoped());
		assertEquals(0, clientDetails.getScope().size());
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		assertNull(clientDetails.getRegisteredRedirectUri());
		assertEquals(0, clientDetails.getAuthorities().size());
		assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
		assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
	}

	@Test
	public void testLoadingClientIdWithAdditionalInformation() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithAddInfo", null, null,
				null, null, null, null, null, null, null);
		jdbcTemplate
				.update("update oauth_client_details set additional_information=? where client_id=?",
						"{\"foo\":\"bar\"}", "clientIdWithAddInfo");

		ClientDetails clientDetails = service
				.loadClientByClientId("clientIdWithAddInfo");

		assertEquals("clientIdWithAddInfo", clientDetails.getClientId());
		assertEquals(Collections.singletonMap("foo", "bar"),
				clientDetails.getAdditionalInformation());
	}

	@Test
	public void testLoadingClientIdWithSingleDetails() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithSingleDetails",
				"mySecret", "myResource", "myScope", "myAuthorizedGrantType",
				"myRedirectUri", "myAuthority", 100, 200, "true");

		ClientDetails clientDetails = service
				.loadClientByClientId("clientIdWithSingleDetails");

		assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(1, clientDetails.getScope().size());
		assertEquals("myScope", clientDetails.getScope().iterator().next());
		assertEquals(1, clientDetails.getResourceIds().size());
		assertEquals("myResource", clientDetails.getResourceIds().iterator()
				.next());
		assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals("myAuthorizedGrantType", clientDetails
				.getAuthorizedGrantTypes().iterator().next());
		assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri()
				.iterator().next());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals("myAuthority", clientDetails.getAuthorities().iterator()
				.next().getAuthority());
		assertEquals(new Integer(100),
				clientDetails.getAccessTokenValiditySeconds());
		assertEquals(new Integer(200),
				clientDetails.getRefreshTokenValiditySeconds());
	}

	@Test
	public void testLoadingClientIdWithSingleDetailsInCustomTable() {
		jdbcTemplate.update(CUSTOM_INSERT_SQL, "clientIdWithSingleDetails",
				"mySecret", "myResource", "myScope", "myAuthorizedGrantType",
				"myRedirectUri", "myAuthority");

		JdbcClientDetailsService customService = new JdbcClientDetailsService(
				db);
		customService
				.setSelectClientDetailsSql("select appId, appSecret, resourceIds, scope, "
						+ "grantTypes, redirectUrl, authorities, access_token_validity, refresh_token_validity, additionalInformation, autoApproveScopes from ClientDetails where appId = ?");

		ClientDetails clientDetails = customService
				.loadClientByClientId("clientIdWithSingleDetails");

		assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(1, clientDetails.getScope().size());
		assertEquals("myScope", clientDetails.getScope().iterator().next());
		assertEquals(1, clientDetails.getResourceIds().size());
		assertEquals("myResource", clientDetails.getResourceIds().iterator()
				.next());
		assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
		assertEquals("myAuthorizedGrantType", clientDetails
				.getAuthorizedGrantTypes().iterator().next());
		assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri()
				.iterator().next());
		assertEquals(1, clientDetails.getAuthorities().size());
		assertEquals("myAuthority", clientDetails.getAuthorities().iterator()
				.next().getAuthority());
	}

	@Test
	public void testLoadingClientIdWithMultipleDetails() {
		jdbcTemplate.update(INSERT_SQL, "clientIdWithMultipleDetails",
				"mySecret", "myResource1,myResource2", "myScope1,myScope2",
				"myAuthorizedGrantType1,myAuthorizedGrantType2",
				"myRedirectUri1,myRedirectUri2", "myAuthority1,myAuthority2",
				100, 200, "read,write");

		ClientDetails clientDetails = service
				.loadClientByClientId("clientIdWithMultipleDetails");

		assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
		assertTrue(clientDetails.isSecretRequired());
		assertEquals("mySecret", clientDetails.getClientSecret());
		assertTrue(clientDetails.isScoped());
		assertEquals(2, clientDetails.getResourceIds().size());
		Iterator<String> resourceIds = clientDetails.getResourceIds()
				.iterator();
		assertEquals("myResource1", resourceIds.next());
		assertEquals("myResource2", resourceIds.next());
		assertEquals(2, clientDetails.getScope().size());
		Iterator<String> scope = clientDetails.getScope().iterator();
		assertEquals("myScope1", scope.next());
		assertEquals("myScope2", scope.next());
		assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
		Iterator<String> grantTypes = clientDetails.getAuthorizedGrantTypes()
				.iterator();
		assertEquals("myAuthorizedGrantType1", grantTypes.next());
		assertEquals("myAuthorizedGrantType2", grantTypes.next());
		assertEquals(2, clientDetails.getRegisteredRedirectUri().size());
		Iterator<String> redirectUris = clientDetails
				.getRegisteredRedirectUri().iterator();
		assertEquals("myRedirectUri1", redirectUris.next());
		assertEquals("myRedirectUri2", redirectUris.next());
		assertEquals(2, clientDetails.getAuthorities().size());
		Iterator<GrantedAuthority> authorities = clientDetails.getAuthorities()
				.iterator();
		assertEquals("myAuthority1", authorities.next().getAuthority());
		assertEquals("myAuthority2", authorities.next().getAuthority());
		assertEquals(new Integer(100),
				clientDetails.getAccessTokenValiditySeconds());
		assertEquals(new Integer(200),
				clientDetails.getRefreshTokenValiditySeconds());
		assertTrue(clientDetails.isAutoApprove("read"));
	}

	@Test
	public void testAddClientWithNoDetails() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("addedClientIdWithNoDetails");

		service.addClientDetails(clientDetails);

		Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
				"addedClientIdWithNoDetails");

		assertEquals("addedClientIdWithNoDetails", map.get("client_id"));
		assertTrue(map.containsKey("client_secret"));
		assertEquals(null, map.get("client_secret"));
	}

	@Test(expected = ClientAlreadyExistsException.class)
	public void testInsertDuplicateClient() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("duplicateClientIdWithNoDetails");

		service.addClientDetails(clientDetails);
		service.addClientDetails(clientDetails);
	}

	@Test
	public void testUpdateClientSecret() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("newClientIdWithNoDetails");

		service.setPasswordEncoder(new PasswordEncoder() {

			public boolean matches(CharSequence rawPassword,
					String encodedPassword) {
				return true;
			}

			public String encode(CharSequence rawPassword) {
				return "BAR";
			}
		});
		service.addClientDetails(clientDetails);
		service.updateClientSecret(clientDetails.getClientId(), "foo");

		Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
				"newClientIdWithNoDetails");

		assertEquals("newClientIdWithNoDetails", map.get("client_id"));
		assertTrue(map.containsKey("client_secret"));
		assertEquals("BAR", map.get("client_secret"));
	}

	@Test
	public void testUpdateClientRedirectURI() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("newClientIdWithNoDetails");

		service.addClientDetails(clientDetails);

		String[] redirectURI = { "http://localhost:8080",
				"http://localhost:9090" };
		clientDetails.setRegisteredRedirectUri(new HashSet<String>(Arrays
				.asList(redirectURI)));

		service.updateClientDetails(clientDetails);

		Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
				"newClientIdWithNoDetails");

		assertEquals("newClientIdWithNoDetails", map.get("client_id"));
		assertTrue(map.containsKey("web_server_redirect_uri"));
		assertEquals("http://localhost:8080,http://localhost:9090",
				map.get("web_server_redirect_uri"));
	}

	@Test(expected = NoSuchClientException.class)
	public void testUpdateNonExistentClient() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("nosuchClientIdWithNoDetails");

		service.updateClientDetails(clientDetails);
	}

	@Test
	public void testRemoveClient() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("deletedClientIdWithNoDetails");

		service.addClientDetails(clientDetails);
		service.removeClientDetails(clientDetails.getClientId());

		int count = jdbcTemplate.queryForObject(
				"select count(*) from oauth_client_details where client_id=?",
				Integer.class, "deletedClientIdWithNoDetails");

		assertEquals(0, count);
	}

	@Test(expected = NoSuchClientException.class)
	public void testRemoveNonExistentClient() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("nosuchClientIdWithNoDetails");

		service.removeClientDetails(clientDetails.getClientId());
	}

	@Test
	public void testFindClients() {

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId("aclient");

		service.addClientDetails(clientDetails);
		int count = service.listClientDetails().size();

		assertEquals(1, count);
	}

}
