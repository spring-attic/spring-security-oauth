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
package org.springframework.security.oauth2.client.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * 
 */
public class AccessTokenRequest implements MultiValueMap<String, String> {

	private final MultiValueMap<String, String> parameters;

	public AccessTokenRequest() {
		this(new LinkedMultiValueMap<String, String>());
	}

	public AccessTokenRequest(LinkedMultiValueMap<String, String> parameters) {
		this.parameters = parameters;
	}

	public AccessTokenRequest(Map<String, String[]> parameters) {
		this();
		for (String key : parameters.keySet()) {
			List<String> values = new ArrayList<String>();
			for (String value : parameters.get(key)) {
				values.add(value);
			}
			this.parameters.put(key, values);
		}
	}
	
	public boolean isError() {
		return parameters.containsKey("error");
	}

	/**
	 * Get the state that has been preserved for the current context.
	 * 
	 * @return the state that has been preserved for the current context.
	 */
	public String getPreservedState() {
		return getFirst("state");
	}

	public void setPreservedState(String state) {
		parameters.set("state", state);
	}

	/**
	 * The URI to which a user is to be redirected after authorizing an access token request for this context.
	 * 
	 * @return The URI to which a user is to be redirected after authorizing an access token request for this context.
	 */
	public String getUserAuthorizationRedirectUri() {
		return getFirst("redirect_uri");
	}

	public void setUserAuthorizationRedirectUri(String uri) {
		parameters.set("redirect_uri", uri);
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

	public String getFirst(String key) {
		return parameters.getFirst(key);
	}

	public void add(String key, String value) {
		parameters.add(key, value);
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

}
