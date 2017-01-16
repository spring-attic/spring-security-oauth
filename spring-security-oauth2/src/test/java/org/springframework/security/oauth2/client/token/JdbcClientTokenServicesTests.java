package org.springframework.security.oauth2.client.token;

import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

/**
 * @author Marcos Barbero
 * @author Dave Syer
 */
public class JdbcClientTokenServicesTests extends ClientTokenServicesBaseTests {

	private JdbcClientTokenServices tokenStore;

	private EmbeddedDatabase db;

	@Override
	public JdbcClientTokenServices getTokenServices() {
		return tokenStore;
	}

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql
		// and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		tokenStore = new JdbcClientTokenServices(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

}
