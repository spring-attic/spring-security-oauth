package org.springframework.security.oauth2.provider.verification;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

public class TestJdbcVerificationCodeServices extends TestVerificationCodeServicesBase {
  private JdbcVerificationCodeServices verificationCodeServices;

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    Class.forName("org.hsqldb.jdbcDriver");
    SingleConnectionDataSource dataSource = new SingleConnectionDataSource("jdbc:hsqldb:mem:lookupstrategytest", "sa", "", true);
    dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    verificationCodeServices = new JdbcVerificationCodeServices(dataSource);
    verificationCodeServices.afterPropertiesSet();

    try {
      jdbcTemplate.execute("drop table oauth_code");
    }
    catch (Exception e) {
      // don't care
    }

    jdbcTemplate.execute("create table oauth_code (code VARCHAR(256), authentication LONGVARBINARY)");
  }

  @Override
  VerificationCodeServices getVerificationCodeServices() {
    return verificationCodeServices;
  }
}
