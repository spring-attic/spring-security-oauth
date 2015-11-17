package org.springframework.security.oauth2.provider.code;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;

import javax.sql.DataSource;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Implementation of authorization code services that stores the codes and authentication in a database.
 * 
 * @author Ken Dombeck
 * @author Dave Syer
 */
public class JdbcAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

	private static final String DEFAULT_SELECT_STATEMENT = "select code, authentication from oauth_code where code = ?";
	private static final String DEFAULT_INSERT_STATEMENT = "insert into oauth_code (code, authentication) values (?, ?)";
	private static final String DEFAULT_DELETE_STATEMENT = "delete from oauth_code where code = ?";
	private static final String DEFAULT_DELETE_EXPIRED_STATEMENT = "delete from oauth_code where created < ?";
	/**
	 *  From RFC6749: A maximum authorization code lifetime of 10 minutes is RECOMMENDED
	 *
	 *  @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">RFC6749 4.1.2.  Authorization Response</a>
	 */
	private static final int DEFAULT_CODE_LIFETIME_SECONDS = 10*60;

	private String selectAuthenticationSql = DEFAULT_SELECT_STATEMENT;
	private String insertAuthenticationSql = DEFAULT_INSERT_STATEMENT;
	private String deleteAuthenticationSql = DEFAULT_DELETE_STATEMENT;
	private String deleteExpiredAuthenticationSql = DEFAULT_DELETE_EXPIRED_STATEMENT;
	private int codeLiftetimeSeconds = DEFAULT_CODE_LIFETIME_SECONDS;

	private final JdbcTemplate jdbcTemplate;

	public JdbcAuthorizationCodeServices(DataSource dataSource) {
		Assert.notNull(dataSource, "DataSource required");
		this.jdbcTemplate = new JdbcTemplate(dataSource);
	}

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		jdbcTemplate.update(insertAuthenticationSql,
				new Object[] { code, new SqlLobValue(SerializationUtils.serialize(authentication)) }, new int[] {
						Types.VARCHAR, Types.BLOB });
	}

	public OAuth2Authentication remove(String code) {
		removeExpired();
		return getAndRemove(code);
	}

	private OAuth2Authentication getAndRemove(String code) {
		OAuth2Authentication authentication;
		try {
			authentication = jdbcTemplate.queryForObject(selectAuthenticationSql,
					new RowMapper<OAuth2Authentication>() {
						public OAuth2Authentication mapRow(ResultSet rs, int rowNum)
								throws SQLException {
							return SerializationUtils.deserialize(rs.getBytes("authentication"));
						}
					}, code);
		} catch (EmptyResultDataAccessException e) {
			return null;
		}

		if (authentication != null) {
			jdbcTemplate.update(deleteAuthenticationSql, code);
		}

		return authentication;
	}

	private void removeExpired() {
		jdbcTemplate.update(deleteExpiredAuthenticationSql, new Timestamp(System.currentTimeMillis() -
			(long)codeLiftetimeSeconds * 1000));
	}

	public void setSelectAuthenticationSql(String selectAuthenticationSql) {
		this.selectAuthenticationSql = selectAuthenticationSql;
	}

	public void setInsertAuthenticationSql(String insertAuthenticationSql) {
		this.insertAuthenticationSql = insertAuthenticationSql;
	}

	public void setDeleteAuthenticationSql(String deleteAuthenticationSql) {
		this.deleteAuthenticationSql = deleteAuthenticationSql;
	}

	public void setDeleteExpiredAuthenticationSql(final String deleteExpiredAuthenticationSql) {
		this.deleteExpiredAuthenticationSql = deleteExpiredAuthenticationSql;
	}

	public void setCodeLiftetimeSeconds(final int codeLiftetimeSeconds) {
		this.codeLiftetimeSeconds = codeLiftetimeSeconds;
	}
}
