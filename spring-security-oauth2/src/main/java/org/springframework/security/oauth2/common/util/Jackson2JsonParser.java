/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.springframework.security.oauth2.common.util;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;



/**
 * @author Dave Syer
 *
 */
public class Jackson2JsonParser implements JsonParser {
	
	private ObjectMapper mapper = new ObjectMapper();

	@SuppressWarnings("unchecked")
	@Override
	public Map<String, Object> parseMap(String json) {
		try {
			return mapper.readValue(json, Map.class);
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Cannot parse json", e);
		}
	}
	
	@Override
	public String formatMap(Map<String, ?> map) {
		try {
			return mapper.writeValueAsString(map);
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Cannot format json", e);
		}
	}

}
