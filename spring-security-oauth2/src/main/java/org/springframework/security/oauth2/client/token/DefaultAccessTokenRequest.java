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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Local context for an access token request encapsulating the parameters that are sent by the client requesting the
 * token, as opposed to the more static variables representing the client itself and the resource being targeted.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultAccessTokenRequest implements AccessTokenRequest, Serializable {

	private static final long serialVersionUID = 914967629530462926L;

	private final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();

	private Object state;

	private OAuth2AccessToken existingToken;

	private String currentUri;

	private String cookie;

	private Map<? extends String, ? extends List<String>> headers = new LinkedMultiValueMap<String, String>();

	public DefaultAccessTokenRequest() {
	}

	public DefaultAccessTokenRequest(Map<String, String[]> parameters) {
		if (parameters!=null) {
			for (Entry<String,String[]> entry : parameters.entrySet()) {
				this.parameters.put(entry.getKey(), Arrays.asList(entry.getValue()));
			}
		}
	}

	public boolean isError() {
		return parameters.containsKey("error");
	}

	public Object getPreservedState() {
		return state;
	}

	public void setPreservedState(Object state) {
		this.state = state;
	}

	public String getStateKey() {
		return getFirst("state");
	}

	public void setStateKey(String state) {
		parameters.set("state", state);
	}

	/**
	 * The current URI that is being handled on the client.
	 * 
	 * @return The URI.
	 */

	public String getCurrentUri() {
		return currentUri;
	}

	public void setCurrentUri(String uri) {
		currentUri = uri;
	}

	/**
	 * The authorization code for this context.
	 * 
	 * @return The authorization code, or null if none.
	 */

	public String getAuthorizationCode() {
		return getFirst("code");
	}

	public void setAuthorizationCode(String code) {
		parameters.set("code", code);
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;	}
	
	public String getCookie() {
		return cookie;
	}
	
	public void setHeaders(Map<? extends String, ? extends List<String>> headers) {
		this.headers = headers;
	}
	
	public Map<? extends String, ? extends List<String>> getHeaders() {
		return headers;
	}

	public void setExistingToken(OAuth2AccessToken existingToken) {
		this.existingToken = existingToken;
	}

	public OAuth2AccessToken getExistingToken() {
		return existingToken;
	}

	public String getFirst(String key) {
		return parameters.getFirst(key);
	}

	public void add(String key, String value) {
		parameters.add(key, value);
	}

	public void addAll(String key, List<String> values) {
		for (String value : values) {
			this.add(key, value);
		}
	}

	public void set(String key, String value) {
		parameters.set(key, value);
	}

	public void setAll(Map<String, String> values) {
		parameters.setAll(values);
	}

	public Map<String, String> toSingleValueMap() {
		return parameters.toSingleValueMap();
	}

	public int size() {
		return parameters.size();
	}

	public boolean isEmpty() {
		return parameters.isEmpty();
	}

	public boolean containsKey(Object key) {
		return parameters.containsKey(key);
	}

	public boolean containsValue(Object value) {
		return parameters.containsValue(value);
	}

	public List<String> get(Object key) {
		return parameters.get(key);
	}

	public List<String> put(String key, List<String> value) {
		return parameters.put(key, value);
	}

	public List<String> remove(Object key) {
		return parameters.remove(key);
	}

	public void putAll(Map<? extends String, ? extends List<String>> m) {
		parameters.putAll(m);
	}

	public void clear() {
		parameters.clear();
	}

	public Set<String> keySet() {
		return parameters.keySet();
	}

	public Collection<List<String>> values() {
		return parameters.values();
	}

	public Set<java.util.Map.Entry<String, List<String>>> entrySet() {
		return parameters.entrySet();
	}

	public boolean equals(Object o) {
		return parameters.equals(o);
	}

	public int hashCode() {
		return parameters.hashCode();
	}
	
	public String toString() {
		return parameters.toString();
	}

}
