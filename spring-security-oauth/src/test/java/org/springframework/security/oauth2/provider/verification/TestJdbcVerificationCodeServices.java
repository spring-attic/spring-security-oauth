package org.springframework.security.oauth2.provider.verification;

import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

public class TestJdbcVerificationCodeServices extends TestVerificationCodeServicesBase {
  private JdbcVerificationCodeServices verificationCodeServices;
  private EmbeddedDatabase db;

  @Override
  public void setUp() throws Exception {
    super.setUp();

    // creates a HSQL in-memory db populated from default scripts classpath:schema.sql and classpath:data.sql
    db = new EmbeddedDatabaseBuilder().addDefaultScripts().build();
    verificationCodeServices = new JdbcVerificationCodeServices(db);
    verificationCodeServices.afterPropertiesSet();
  }

  @Override
  public void tearDown() throws Exception {
    super.tearDown();
    db.shutdown();
  }

  @Override
  VerificationCodeServices getVerificationCodeServices() {
    return verificationCodeServices;
  }
}
