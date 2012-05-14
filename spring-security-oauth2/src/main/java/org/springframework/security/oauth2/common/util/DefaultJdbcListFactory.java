/*
 * Copyright 2002-2011 the original author or authors.
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

package org.springframework.security.oauth2.common.util;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;

/**
 * @author Dave Syer
 *
 */
public class DefaultJdbcListFactory implements JdbcListFactory {

	private final NamedParameterJdbcOperations jdbcTemplate;

	/**
	 * @param jdbcTemplate the jdbc template to use
	 */
	public DefaultJdbcListFactory(NamedParameterJdbcOperations jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	public <T> List<T> getList(String sql, Map<String, Object> parameters, RowMapper<T> rowMapper) {
		return jdbcTemplate.query(sql, parameters, rowMapper);
	}

}
