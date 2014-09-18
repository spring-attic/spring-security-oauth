/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.approval;

import static org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus.APPROVED;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 * 
 */
public class JdbcApprovalStore implements ApprovalStore {

	private final JdbcTemplate jdbcTemplate;

	private final Log logger = LogFactory.getLog(getClass());

	private final RowMapper<Approval> rowMapper = new AuthorizationRowMapper();
	
	private static final String TABLE_NAME = "oauth_approvals";

	private static final String FIELDS = "expiresAt,status,lastModifiedAt,userId,clientId,scope";

	private static final String WHERE_KEY = "where userId=? and clientId=?";

	private static final String WHERE_KEY_AND_SCOPE =  WHERE_KEY + " and scope=?";

	private static final String DEFAULT_ADD_APPROVAL_STATEMENT = String.format("insert into %s ( %s ) values (?,?,?,?,?,?)", TABLE_NAME,
			FIELDS);

	private static final String DEFAULT_REFRESH_APPROVAL_STATEMENT = String.format(
			"update %s set expiresAt=?, status=?, lastModifiedAt=? " + WHERE_KEY_AND_SCOPE, TABLE_NAME);

	private static final String DEFAULT_GET_APPROVAL_SQL = String.format("select %s from %s " + WHERE_KEY, FIELDS, TABLE_NAME);

	private static final String DEFAULT_DELETE_APPROVAL_SQL = String.format("delete from %s " + WHERE_KEY_AND_SCOPE,
			TABLE_NAME);

	private static final String DEFAULT_EXPIRE_APPROVAL_STATEMENT = String.format("update %s set expiresAt = ? " + WHERE_KEY_AND_SCOPE,
			TABLE_NAME);

	private String addApprovalStatement = DEFAULT_ADD_APPROVAL_STATEMENT;

	private String refreshApprovalStatement = DEFAULT_REFRESH_APPROVAL_STATEMENT;

	private  String findApprovalStatement = DEFAULT_GET_APPROVAL_SQL;

	private String deleteApprovalStatment = DEFAULT_DELETE_APPROVAL_SQL;

	private String expireApprovalStatement = DEFAULT_EXPIRE_APPROVAL_STATEMENT;

	private boolean handleRevocationsAsExpiry = false;

	public JdbcApprovalStore(DataSource dataSource) {
		Assert.notNull(dataSource);
		this.jdbcTemplate = new JdbcTemplate(dataSource);
	}

	public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
		this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
	}

	public void setAddApprovalStatement(String addApprovalStatement) {
		this.addApprovalStatement = addApprovalStatement;
	}

	public void setFindApprovalStatement(String findApprovalStatement) {
		this.findApprovalStatement = findApprovalStatement;
	}

	public void setDeleteApprovalStatment(String deleteApprovalStatment) {
		this.deleteApprovalStatment = deleteApprovalStatment;
	}

	public void setExpireApprovalStatement(String expireApprovalStatement) {
		this.expireApprovalStatement = expireApprovalStatement;
	}
	
	public void setRefreshApprovalStatement(String refreshApprovalStatement) {
		this.refreshApprovalStatement = refreshApprovalStatement;
	}

	@Override
	public boolean addApprovals(final Collection<Approval> approvals) {
		logger.debug(String.format("adding approvals: [%s]", approvals));
		boolean success = true;
		for (Approval approval : approvals) {
			if (!updateApproval(refreshApprovalStatement, approval)) {
				if (!updateApproval(addApprovalStatement, approval)) {
					success = false;
				}
			}
		}
		return success;
	}

	@Override
	public boolean revokeApprovals(Collection<Approval> approvals) {
		logger.debug(String.format("Revoking approvals: [%s]", approvals));
		boolean success = true;
		for (final Approval approval : approvals) {
			if (handleRevocationsAsExpiry) {
				int refreshed = jdbcTemplate.update(expireApprovalStatement, new PreparedStatementSetter() {
					@Override
					public void setValues(PreparedStatement ps) throws SQLException {
						ps.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
						ps.setString(2, approval.getUserId());
						ps.setString(3, approval.getClientId());
						ps.setString(4, approval.getScope());
					}
				});
				if (refreshed != 1) {
					success = false;
				}
			}
			else {
				int refreshed = jdbcTemplate.update(deleteApprovalStatment, new PreparedStatementSetter() {
					@Override
					public void setValues(PreparedStatement ps) throws SQLException {
						ps.setString(1, approval.getUserId());
						ps.setString(2, approval.getClientId());
						ps.setString(3, approval.getScope());
					}
				});
				if (refreshed != 1) {
					success = false;
				}
			}
		}
		return success;
	}

	public boolean purgeExpiredApprovals() {
		logger.debug("Purging expired approvals from database");
		try {
			int deleted = jdbcTemplate.update(deleteApprovalStatment + " where expiresAt <= ?",
					new PreparedStatementSetter() {
						@Override
						public void setValues(PreparedStatement ps) throws SQLException {
							ps.setTimestamp(1, new Timestamp(new Date().getTime()));
						}
					});
			logger.debug(deleted + " expired approvals deleted");
		}
		catch (DataAccessException ex) {
			logger.error("Error purging expired approvals", ex);
			return false;
		}
		return true;
	}

	@Override
	public List<Approval> getApprovals(String userName, String clientId) {
		return jdbcTemplate.query(findApprovalStatement, rowMapper, userName, clientId);
	}

	private boolean updateApproval(final String sql, final Approval approval) {
		logger.debug(String.format("refreshing approval: [%s]", approval));
		int refreshed = jdbcTemplate.update(sql, new PreparedStatementSetter() {
			@Override
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setTimestamp(1, new Timestamp(approval.getExpiresAt().getTime()));
				ps.setString(2, (approval.getStatus() == null ? APPROVED : approval.getStatus()).toString());
				ps.setTimestamp(3, new Timestamp(approval.getLastUpdatedAt().getTime()));
				ps.setString(4, approval.getUserId());
				ps.setString(5, approval.getClientId());
				ps.setString(6, approval.getScope());
			}
		});
		if (refreshed != 1) {
			return false;
		}
		return true;
	}

	private static class AuthorizationRowMapper implements RowMapper<Approval> {

		@Override
		public Approval mapRow(ResultSet rs, int rowNum) throws SQLException {
			String userName = rs.getString(4);
			String clientId = rs.getString(5);
			String scope = rs.getString(6);
			Date expiresAt = rs.getTimestamp(1);
			String status = rs.getString(2);
			Date lastUpdatedAt = rs.getTimestamp(3);

			return new Approval(userName, clientId, scope, expiresAt, ApprovalStatus.valueOf(status), lastUpdatedAt);
		}
	}
}
