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

/**
 * @author Dave Syer
 *
 */
public interface JsonParser {

	/**
	 * Parse the specified JSON string into a Map.
	 * @param json the JSON to parse
	 * @return the parsed JSON as a map
	 */
	Map<String, Object> parseMap(String json);
	
	/**
	 * Convert the Map to JSON
	 * @param map a map to format
	 * @return a JSON representation of the map
	 */
	String formatMap(Map<String, ?> map);

}
