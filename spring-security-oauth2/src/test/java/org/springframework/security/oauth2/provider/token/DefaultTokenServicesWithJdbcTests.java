package org.springframework.security.oauth2.provider.token;

import org.junit.After;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class DefaultTokenServicesWithJdbcTests extends AbstractPersistentDefaultTokenServicesTests {

	private EmbeddedDatabase db;

	protected TokenStore createTokenStore() {
		db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
		return new JdbcTokenStore(db);
	}

	@After
	public void tearDown() throws Exception {
		db.shutdown();
	}


	protected int getAccessTokenCount() {
		return new JdbcTemplate(db).queryForObject("SELECT COUNT(*) FROM OAUTH_ACCESS_TOKEN", Integer.class);
	}

	protected int getRefreshTokenCount() {
		return new JdbcTemplate(db).queryForObject("SELECT COUNT(*) FROM OAUTH_REFRESH_TOKEN", Integer.class);
	}

}
