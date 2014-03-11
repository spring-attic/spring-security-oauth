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
package org.springframework.security.oauth2.client.token;

import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

public interface AccessTokenRequest extends MultiValueMap<String, String> {

	OAuth2AccessToken getExistingToken();

	void setExistingToken(OAuth2AccessToken existingToken);

	void setAuthorizationCode(String code);

	String getAuthorizationCode();

	void setCurrentUri(String uri);

	String getCurrentUri();

	void setStateKey(String state);

	String getStateKey();

	void setPreservedState(Object state);

	Object getPreservedState();

	boolean isError();

	void setCookie(String cookie);

	String getCookie();
	
	void setHeaders(Map<? extends String, ? extends List<String>> headers);

	Map<? extends String, ? extends List<String>> getHeaders();

}