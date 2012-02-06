/*
 * Copyright 2006-2011 the original author or authors.
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
package org.springframework.security.oauth2.common;

/**
 * Enumeration of possible methods for transmitting authentication credentials.
 */
public enum AuthenticationScheme {

	/**
	 * Send an Authorization header.
	 */
	header,

	/**
	 * Send a query parameter in the URI.
	 */
	query,

	/**
	 * Send in the form body.
	 */
	form,

	/**
	 * Do not send at all.
	 */
	none
}