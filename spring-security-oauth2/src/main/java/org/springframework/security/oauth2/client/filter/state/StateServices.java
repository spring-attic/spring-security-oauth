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

package org.springframework.security.oauth2.client.filter.state;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Dave Syer
 *
 */
public interface StateServices {

	/**
	   * Preserve the specified state for the given resource.
	   *
	   * @param id The id state to preserve. Possibly null, in which case it indicates to load the global state, if any.
	   * @param state The state to preserve.
	   * @param request The request.
	   * @param response The response.
	   */
	  void preserveState(String id, Object state, HttpServletRequest request, HttpServletResponse response);

	/**
	   * Load the preserved state for the given request.
	   *
	   * @param state The id the preserved state. Possibly null, in which case it indicates to load the global state, if any.
	   * @param request The request.
	   * @param response The response.
	   * @return The preserved state (mapped by resource id), or null if none is remembered.
	   */
	  Object loadPreservedState(String state, HttpServletRequest request, HttpServletResponse response);

}
