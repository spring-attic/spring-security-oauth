package org.springframework.security.oauth2.provider.token;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

public class TestJdbcOAuth2ProviderTokenServices extends TestRandomValueOAuth2ProviderTokenServicesBase {
  private JdbcOAuth2ProviderTokenServices oauth2ProviderTokenServices;

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    Class.forName("org.hsqldb.jdbcDriver");
    SingleConnectionDataSource dataSource = new SingleConnectionDataSource("jdbc:hsqldb:mem:lookupstrategytest", "sa", "", true);
    dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    oauth2ProviderTokenServices = new JdbcOAuth2ProviderTokenServices(dataSource);
    oauth2ProviderTokenServices.afterPropertiesSet();

    try {
      jdbcTemplate.execute("drop table oauth_access_token");
    }
    catch (Exception e) {
      // don't care
    }

    try {
      jdbcTemplate.execute("drop table oauth_refresh_token");
    }
    catch (Exception e) {
      // don't care
    }

    jdbcTemplate.execute("create table oauth_access_token (token_id VARCHAR(256), token LONGVARBINARY, authentication LONGVARBINARY)");
    jdbcTemplate.execute("create table oauth_refresh_token (token_id VARCHAR(256), token LONGVARBINARY, authentication LONGVARBINARY)");
  }

  @Override
  RandomValueOAuth2ProviderTokenServices getRandomValueOAuth2ProviderTokenServices() {
    return oauth2ProviderTokenServices;
  }
}
