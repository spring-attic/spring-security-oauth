/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;

/**
 * Basic, JDBC implementation of the client details service.
 */
public class JdbcClientDetailsService implements ClientDetailsService {

	private static final String DEFAULT_SELECT_STATEMENT = "select client_id, resource_ids, client_secret, scope, "
			+ "authorized_grant_types, authorities, access_token_validity from oauth_client_details where client_id = ?";

	private static final String DEFAULT_SELECT_REDIRECT_URIS_STATEMENT = "select web_server_redirect_uri from "
			+ "oauth_client_redirect_uri where client_id = ?";

	private String selectClientDetailsSql = DEFAULT_SELECT_STATEMENT;

	private String selectClientRedirectUrisStatment = DEFAULT_SELECT_REDIRECT_URIS_STATEMENT;

	private final JdbcTemplate jdbcTemplate;

	public JdbcClientDetailsService(DataSource dataSource) {
		Assert.notNull(dataSource, "DataSource required");
		this.jdbcTemplate = new JdbcTemplate(dataSource);
	}

	public ClientDetails loadClientByClientId(final String clientId) throws OAuth2Exception {
		ClientDetails details;
		try {
			details = jdbcTemplate.queryForObject(selectClientDetailsSql, new RowMapper<ClientDetails>() {
				public ClientDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
					BaseClientDetails details = new BaseClientDetails(rs.getString(2), rs.getString(4), rs.getString(5),
																	  rs.getString(6));
					details.setClientId(rs.getString(1));
					details.setClientSecret(rs.getString(3));
					details.setAccessTokenValiditySeconds(rs.getInt(7));
					List<String> uris = jdbcTemplate.queryForList(selectClientRedirectUrisStatment, String.class, clientId);
					details.setRegisteredRedirectUri(uris.isEmpty() ? null : new HashSet<String>(uris));
					return details;
				}
			}, clientId);
		}
		catch (EmptyResultDataAccessException e) {
			throw new InvalidClientException("Client not found: " + clientId);
		}

		return details;
	}

	public void setSelectClientDetailsSql(String selectClientDetailsSql) {
		this.selectClientDetailsSql = selectClientDetailsSql;
	}

	public void setSelectClientRedirectUrisSql(String selectClientRedirectUrisSql) {
		this.selectClientRedirectUrisStatment = selectClientRedirectUrisSql;
	}
}
