package org.springframework.security.oauth2.provider.token;

import org.junit.After;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

/**
 * @author Dave Syer
 * 
 */
public class TestDefaultTokenServicesWithJdbc extends AbstractTestDefaultTokenServices {

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
		return new JdbcTemplate(db).queryForInt("SELECT COUNT(*) FROM OAUTH_ACCESS_TOKEN");
	}

	protected int getRefreshTokenCount() {
		return new JdbcTemplate(db).queryForInt("SELECT COUNT(*) FROM OAUTH_REFRESH_TOKEN");
	}

}
