package org.springframework.security.oauth2.provider.token;

import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

/**
 * @author Dave Syer
 *
 */
public class TestJdbcTokenStore extends TestTokenStoreBase {

	private JdbcTokenStore tokenStore;

	private EmbeddedDatabase db;

	@Override
	public JdbcTokenStore getTokenStore() {
		return tokenStore;
	}
	
	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		tokenStore = new JdbcTokenStore(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

}
