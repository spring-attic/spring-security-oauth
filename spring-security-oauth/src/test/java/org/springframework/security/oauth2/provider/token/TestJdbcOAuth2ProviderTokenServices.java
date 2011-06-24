package org.springframework.security.oauth2.provider.token;

import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

public class TestJdbcOAuth2ProviderTokenServices extends TestRandomValueOAuth2ProviderTokenServicesBase {
  private JdbcOAuth2ProviderTokenServices oauth2ProviderTokenServices;
  private EmbeddedDatabase db;

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    // creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
    db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
    oauth2ProviderTokenServices = new JdbcOAuth2ProviderTokenServices(db);
    oauth2ProviderTokenServices.afterPropertiesSet();
  }

  @Override
  public void tearDown() throws Exception {
    super.tearDown();
    db.shutdown();
  }

  @Override
  RandomValueOAuth2ProviderTokenServices getRandomValueOAuth2ProviderTokenServices() {
    return oauth2ProviderTokenServices;
  }
}
