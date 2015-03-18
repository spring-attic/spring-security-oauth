package org.springframework.security.oauth2.client.token;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.util.Assert;

/**
 * Implementation of token services that stores tokens in a database for retrieval by client applications.
 * 
 * @author Dave Syer
 */
public class JdbcClientTokenServices implements ClientTokenServices {

	private static final Log LOG = LogFactory.getLog(JdbcClientTokenServices.class);

	private static final String DEFAULT_ACCESS_TOKEN_INSERT_STATEMENT = "insert into oauth_client_token (token_id, token, authentication_id, user_name, client_id) values (?, ?, ?, ?, ?)";

	private static final String DEFAULT_ACCESS_TOKEN_FROM_AUTHENTICATION_SELECT_STATEMENT = "select token_id, token from oauth_client_token where authentication_id = ?";

	private static final String DEFAULT_ACCESS_TOKEN_DELETE_STATEMENT = "delete from oauth_client_token where authentication_id = ?";

	private String insertAccessTokenSql = DEFAULT_ACCESS_TOKEN_INSERT_STATEMENT;

	private String selectAccessTokenSql = DEFAULT_ACCESS_TOKEN_FROM_AUTHENTICATION_SELECT_STATEMENT;

	private String deleteAccessTokenSql = DEFAULT_ACCESS_TOKEN_DELETE_STATEMENT;

	private ClientKeyGenerator keyGenerator = new DefaultClientKeyGenerator();

	private final JdbcTemplate jdbcTemplate;

	public JdbcClientTokenServices(DataSource dataSource) {
		Assert.notNull(dataSource, "DataSource required");
		this.jdbcTemplate = new JdbcTemplate(dataSource);
	}

	public void setClientKeyGenerator(ClientKeyGenerator keyGenerator) {
		this.keyGenerator = keyGenerator;
	}

	public OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {

		OAuth2AccessToken accessToken = null;

		try {
			accessToken = jdbcTemplate.queryForObject(selectAccessTokenSql, new RowMapper<OAuth2AccessToken>() {
				public OAuth2AccessToken mapRow(ResultSet rs, int rowNum) throws SQLException {
					return SerializationUtils.deserialize(rs.getBytes(2));
				}
			}, keyGenerator.extractKey(resource, authentication));
		}
		catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.debug("Failed to find access token for authentication " + authentication);
			}
		}

		return accessToken;
	}

	public void saveAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication,
			OAuth2AccessToken accessToken) {
		removeAccessToken(resource, authentication);
		String name = authentication==null ? null : authentication.getName();
		jdbcTemplate.update(
				insertAccessTokenSql,
				new Object[] { accessToken.getValue(), new SqlLobValue(SerializationUtils.serialize(accessToken)),
						keyGenerator.extractKey(resource, authentication), name,
						resource.getClientId() }, new int[] { Types.VARCHAR, Types.BLOB, Types.VARCHAR, Types.VARCHAR,
						Types.VARCHAR });
	}

	public void removeAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {
		jdbcTemplate.update(deleteAccessTokenSql, keyGenerator.extractKey(resource, authentication));
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

}
