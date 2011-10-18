package org.springframework.security.oauth2.provider.token;

import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

public class TestJdbcOAuth2ProviderTokenServices extends TestRandomValueOAuth2ProviderTokenServicesBase {
	private JdbcTokenStore tokenStore;
	private EmbeddedDatabase db;

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

	@Override
	TokenStore getTokenStore() {
		return tokenStore;
	}
}
