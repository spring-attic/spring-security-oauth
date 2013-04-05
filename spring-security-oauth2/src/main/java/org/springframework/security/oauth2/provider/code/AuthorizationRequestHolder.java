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

package org.springframework.security.oauth2.provider.code;

import java.io.Serializable;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * Convenience class for {@link AuthorizationCodeServices} to store and retrieve.
 * 
 * @author Dave Syer
 * 
 */
public class AuthorizationRequestHolder implements Serializable {

	private static final long serialVersionUID = 914967629530462926L;

	private final OAuth2Request oAuth2Request;

	private final Authentication userAuthentication;

	public AuthorizationRequestHolder(
			OAuth2Request oAuth2Request, Authentication userAuthentication) {
		this.oAuth2Request = oAuth2Request;
		this.userAuthentication = userAuthentication;
	}

	public OAuth2Request getAuthenticationRequest() {
		return oAuth2Request;
	}

	public Authentication getUserAuthentication() {
		return userAuthentication;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((oAuth2Request == null) ? 0 : oAuth2Request.hashCode());
		result = prime * result + ((userAuthentication == null) ? 0 : userAuthentication.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AuthorizationRequestHolder other = (AuthorizationRequestHolder) obj;
		if (oAuth2Request == null) {
			if (other.oAuth2Request != null)
				return false;
		} else if (!oAuth2Request.equals(other.oAuth2Request))
			return false;
		if (userAuthentication == null) {
			if (other.userAuthentication != null)
				return false;
		} else if (!userAuthentication.equals(other.userAuthentication))
			return false;
		return true;
	}

}
