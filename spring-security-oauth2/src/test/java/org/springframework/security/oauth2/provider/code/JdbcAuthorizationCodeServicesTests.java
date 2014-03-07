package org.springframework.security.oauth2.provider.code;

import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

public class JdbcAuthorizationCodeServicesTests extends AuthorizationCodeServicesBaseTests {
	private JdbcAuthorizationCodeServices authorizationCodeServices;

	private EmbeddedDatabase db;

	@Before
	public void setUp() throws Exception {
		// creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		authorizationCodeServices = new JdbcAuthorizationCodeServices(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}

	@Override
	AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices;
	}
}
