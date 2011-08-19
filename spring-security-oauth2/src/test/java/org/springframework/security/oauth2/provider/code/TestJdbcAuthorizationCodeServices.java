package org.springframework.security.oauth2.provider.code;

import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;

public class TestJdbcAuthorizationCodeServices extends TestAuthorizationCodeServicesBase {
  private JdbcAuthorizationCodeServices verificationCodeServices;
  private EmbeddedDatabase db;

  @Before
  public void setUp() throws Exception {
     // creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
    db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
    verificationCodeServices = new JdbcAuthorizationCodeServices(db);
    verificationCodeServices.afterPropertiesSet();
  }

  @After
  public void tearDown() throws Exception {
    db.shutdown();
  }

  @Override
  AuthorizationCodeServices getVerificationCodeServices() {
    return verificationCodeServices;
  }
}
