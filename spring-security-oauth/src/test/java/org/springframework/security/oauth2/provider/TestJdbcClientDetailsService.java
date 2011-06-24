package org.springframework.security.oauth2.provider;

import junit.framework.TestCase;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;

public class TestJdbcClientDetailsService extends TestCase {
  private JdbcClientDetailsService service;
  private JdbcTemplate jdbcTemplate;
  private EmbeddedDatabase db;

  private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, scope, authorized_grant_types, web_server_redirect_uri, authorities) values (?, ?, ?, ?, ?, ?)";

  @Override
  public void setUp() throws Exception {
    super.setUp();

    // creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
    db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
    jdbcTemplate = new JdbcTemplate(db);
    service = new JdbcClientDetailsService(db);
  }

  @Override
  public void tearDown() throws Exception {
    super.tearDown();
    db.shutdown();
  }

  public void testLoadingClientForNonExsitingClientId() {
    try {
      service.loadClientByClientId("nonExistingClientId");
      fail("Should have thrown exception");
    } catch (InvalidClientException e) {
      // valid
    }
  }

  public void testLoadingClientIdWithNoDetails() {
    jdbcTemplate.update(INSERT_SQL, "clientIdWithNoDetails", null, null, null, null, null);

    ClientDetails clientDetails = service.loadClientByClientId("clientIdWithNoDetails");

    assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
    assertFalse(clientDetails.isSecretRequired());
    assertNull(clientDetails.getClientSecret());
    assertFalse(clientDetails.isScoped());
    assertNull(clientDetails.getScope());
    assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
    assertNull(clientDetails.getWebServerRedirectUri());
    assertEquals(0, clientDetails.getAuthorities().size());
  }

  public void testLoadingClientIdWithSingleDetails() {
    jdbcTemplate.update(INSERT_SQL, "clientIdWithSingleDetails", "mySecret", "myScope", "myAuthorizedGrantType", "myRedirectUri", "myAuthority");

    ClientDetails clientDetails = service.loadClientByClientId("clientIdWithSingleDetails");

    assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
    assertTrue(clientDetails.isSecretRequired());
    assertEquals("mySecret", clientDetails.getClientSecret());
    assertTrue(clientDetails.isScoped());
    assertEquals(1, clientDetails.getScope().size());
    assertEquals("myScope", clientDetails.getScope().get(0));
    assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
    assertEquals("myAuthorizedGrantType", clientDetails.getAuthorizedGrantTypes().get(0));
    assertEquals("myRedirectUri", clientDetails.getWebServerRedirectUri());
    assertEquals(1, clientDetails.getAuthorities().size());
    assertEquals("myAuthority", clientDetails.getAuthorities().get(0).getAuthority());
  }

  public void testLoadingClientIdWithMultipleDetails() {
    jdbcTemplate.update(INSERT_SQL, "clientIdWithMultipleDetails", "mySecret", "myScope1,myScope2", "myAuthorizedGrantType1,myAuthorizedGrantType2", "myRedirectUri", "myAuthority1,myAuthority2");

    ClientDetails clientDetails = service.loadClientByClientId("clientIdWithMultipleDetails");

    assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
    assertTrue(clientDetails.isSecretRequired());
    assertEquals("mySecret", clientDetails.getClientSecret());
    assertTrue(clientDetails.isScoped());
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
