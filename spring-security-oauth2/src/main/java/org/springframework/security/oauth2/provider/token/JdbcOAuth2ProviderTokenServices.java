package org.springframework.security.oauth2.provider.token;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Implementation of token services that stores tokens in a database.
 *
 * @author Ken Dombeck
 */
public class JdbcOAuth2ProviderTokenServices extends RandomValueOAuth2ProviderTokenServices {

  private static final Log LOG = LogFactory.getLog(JdbcOAuth2ProviderTokenServices.class);

  private static final String DEFAULT_ACCESS_TOKEN_INSERT_STATEMENT = "insert into oauth_access_token (token_id, token, authentication, refresh_token) values (?, ?, ?, ?)";
  private static final String DEFAULT_ACCESS_TOKEN_SELECT_STATEMENT = "select token_id, token from oauth_access_token where token_id = ?";
  private static final String DEFAULT_ACCESS_TOKEN_AUTHENTICATION_SELECT_STATEMENT = "select token_id, authentication from oauth_access_token where token_id = ?";
  private static final String DEFAULT_ACCESS_TOKEN_DELETE_STATEMENT = "delete from oauth_access_token where token_id = ?";
  private static final String DEFAULT_ACCESS_TOKEN_DELETE_FROM_REFRESH_TOKEN_STATEMENT = "delete from oauth_access_token where refresh_token = ?";

  private static final String DEFAULT_REFRESH_TOKEN_INSERT_STATEMENT = "insert into oauth_refresh_token (token_id, token, authentication) values (?, ?, ?)";
  private static final String DEFAULT_REFRESH_TOKEN_SELECT_STATEMENT = "select token_id, token from oauth_refresh_token where token_id = ?";
  private static final String DEFAULT_REFRESH_TOKEN_AUTHENTICATION_SELECT_STATEMENT = "select token_id, authentication from oauth_refresh_token where token_id = ?";
  private static final String DEFAULT_REFRESH_TOKEN_DELETE_STATEMENT = "delete from oauth_refresh_token where token_id = ?";

  private String insertAccessTokenSql = DEFAULT_ACCESS_TOKEN_INSERT_STATEMENT;
  private String selectAccessTokenSql = DEFAULT_ACCESS_TOKEN_SELECT_STATEMENT;
  private String selectAccessTokenAuthenticationSql = DEFAULT_ACCESS_TOKEN_AUTHENTICATION_SELECT_STATEMENT;
  private String deleteAccessTokenSql = DEFAULT_ACCESS_TOKEN_DELETE_STATEMENT;

  private String insertRefreshTokenSql = DEFAULT_REFRESH_TOKEN_INSERT_STATEMENT;
  private String selectRefreshTokenSql = DEFAULT_REFRESH_TOKEN_SELECT_STATEMENT;
  private String selectRefreshTokenAuthenticationSql = DEFAULT_REFRESH_TOKEN_AUTHENTICATION_SELECT_STATEMENT;
  private String deleteRefreshTokenSql = DEFAULT_REFRESH_TOKEN_DELETE_STATEMENT;

  private String deleteAccessTokenFromRefreshTokenSql = DEFAULT_ACCESS_TOKEN_DELETE_FROM_REFRESH_TOKEN_STATEMENT;

  private final JdbcTemplate jdbcTemplate;

  public JdbcOAuth2ProviderTokenServices(DataSource dataSource) {
    Assert.notNull(dataSource, "DataSource required");
    this.jdbcTemplate = new JdbcTemplate(dataSource);
  }

  @Override
  protected void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
    String refreshToken = null;
    if (token.getRefreshToken() != null) {
      refreshToken = token.getRefreshToken().getValue();
    }

    jdbcTemplate.update(insertAccessTokenSql,
                        new Object[] {
                          token.getValue(),
                          new SqlLobValue(SerializationUtils.serialize(token)),
                          new SqlLobValue(SerializationUtils.serialize(authentication)),
                          refreshToken
                        },
                        new int[]{Types.VARCHAR, Types.BLOB, Types.BLOB, Types.VARCHAR});
  }

  @Override
  protected OAuth2AccessToken readAccessToken(String tokenValue) {
    OAuth2AccessToken accessToken = null;

    try {
      accessToken = jdbcTemplate.queryForObject(selectAccessTokenSql,
                                                new RowMapper<OAuth2AccessToken>() {
                                                  public OAuth2AccessToken mapRow(ResultSet rs, int rowNum) throws SQLException {
                                                    return SerializationUtils.deserialize(rs.getBytes(2));
                                                  }
                                                }, tokenValue);
    }
    catch (EmptyResultDataAccessException e) {
      if (LOG.isInfoEnabled()) {
        LOG.info("Failed to find access token for token " + tokenValue);
      }
    }

    return accessToken;
  }

  @Override
  protected void removeAccessToken(String tokenValue) {
    jdbcTemplate.update(deleteAccessTokenSql, tokenValue);
  }

  @Override
  protected OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
    OAuth2Authentication authentication = null;

    try {
      authentication = jdbcTemplate.queryForObject(selectAccessTokenAuthenticationSql,
                                                   new RowMapper<OAuth2Authentication>() {
                                                     public OAuth2Authentication mapRow(ResultSet rs, int rowNum) throws SQLException {
                                                       return SerializationUtils.deserialize(rs.getBytes(2));
                                                     }
                                                   }, token.getValue());
    }
    catch (EmptyResultDataAccessException e) {
      if (LOG.isInfoEnabled()) {
        LOG.info("Failed to find access token for token " + token);
      }
    }

    return authentication;
  }

  @Override
  protected void storeRefreshToken(ExpiringOAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
    jdbcTemplate.update(insertRefreshTokenSql,
                        new Object[]{refreshToken.getValue(),
                          new SqlLobValue(SerializationUtils.serialize(refreshToken)),
                          new SqlLobValue(SerializationUtils.serialize(authentication))},
                        new int[]{Types.VARCHAR, Types.BLOB, Types.BLOB});
  }

  @Override
  protected ExpiringOAuth2RefreshToken readRefreshToken(String token) {
    ExpiringOAuth2RefreshToken refreshToken = null;

    try {
      refreshToken = jdbcTemplate.queryForObject(selectRefreshTokenSql,
                                                 new RowMapper<ExpiringOAuth2RefreshToken>() {
                                                   public ExpiringOAuth2RefreshToken mapRow(ResultSet rs, int rowNum) throws SQLException {
                                                     return SerializationUtils.deserialize(rs.getBytes(2));
                                                   }
                                                 }, token);
    }
    catch (EmptyResultDataAccessException e) {
      if (LOG.isInfoEnabled()) {
        LOG.info("Failed to find refresh token for token " + token);
      }
    }

    return refreshToken;
  }

  @Override
  protected void removeRefreshToken(String token) {
    jdbcTemplate.update(deleteRefreshTokenSql, token);
  }

  @Override
  protected OAuth2Authentication readAuthentication(ExpiringOAuth2RefreshToken token) {
    OAuth2Authentication authentication = null;

    try {
      authentication = jdbcTemplate.queryForObject(selectRefreshTokenAuthenticationSql,
                                                   new RowMapper<OAuth2Authentication>() {
                                                     public OAuth2Authentication mapRow(ResultSet rs, int rowNum) throws SQLException {
                                                       return SerializationUtils.deserialize(rs.getBytes(2));
                                                     }
                                                   }, token.getValue());
    }
    catch (EmptyResultDataAccessException e) {
      if (LOG.isInfoEnabled()) {
        LOG.info("Failed to find access token for token " + token);
      }
    }

    return authentication;
  }

  @Override
  protected void removeAccessTokenUsingRefreshToken(String refreshToken) {
    jdbcTemplate.update(deleteAccessTokenFromRefreshTokenSql,
                        new Object[]{refreshToken},
                        new int[]{Types.VARCHAR});
  }

  public void setInsertAccessTokenSql(String insertAccessTokenSql) {
    this.insertAccessTokenSql = insertAccessTokenSql;
  }

  public void setSelectAccessTokenSql(String selectAccessTokenSql) {
    this.selectAccessTokenSql = selectAccessTokenSql;
  }

  public void setDeleteAccessTokenSql(String deleteAccessTokenSql) {
    this.deleteAccessTokenSql = deleteAccessTokenSql;
  }

  public void setInsertRefreshTokenSql(String insertRefreshTokenSql) {
    this.insertRefreshTokenSql = insertRefreshTokenSql;
  }

  public void setSelectRefreshTokenSql(String selectRefreshTokenSql) {
    this.selectRefreshTokenSql = selectRefreshTokenSql;
  }

  public void setDeleteRefreshTokenSql(String deleteRefreshTokenSql) {
    this.deleteRefreshTokenSql = deleteRefreshTokenSql;
  }

  public void setSelectAccessTokenAuthenticationSql(String selectAccessTokenAuthenticationSql) {
    this.selectAccessTokenAuthenticationSql = selectAccessTokenAuthenticationSql;
  }

  public void setSelectRefreshTokenAuthenticationSql(String selectRefreshTokenAuthenticationSql) {
    this.selectRefreshTokenAuthenticationSql = selectRefreshTokenAuthenticationSql;
  }

  public void setDeleteAccessTokenFromRefreshTokenSql(String deleteAccessTokenFromRefreshTokenSql) {
    this.deleteAccessTokenFromRefreshTokenSql = deleteAccessTokenFromRefreshTokenSql;
  }
}
