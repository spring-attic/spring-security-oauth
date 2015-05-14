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


package org.springframework.security.oauth2.provider.authentication;

import java.io.Serializable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * A holder of selected HTTP details related to an OAuth2 authentication request.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationDetails implements Serializable {
	
	private static final long serialVersionUID = -4809832298438307309L;

	public static final String ACCESS_TOKEN_VALUE = OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_VALUE";

	public static final String ACCESS_TOKEN_TYPE = OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_TYPE";

	private final String remoteAddress;

	private final String sessionId;

	private final String tokenValue;

	private final String tokenType;

	private final String display;
	
	private Object decodedDetails;


	/**
	 * Records the access token value and remote address and will also set the session Id if a session already exists
	 * (it won't create one).
	 * 
	 * @param request that the authentication request was received from
	 */
	public OAuth2AuthenticationDetails(HttpServletRequest request) {
		this.tokenValue = (String) request.getAttribute(ACCESS_TOKEN_VALUE);
		this.tokenType = (String) request.getAttribute(ACCESS_TOKEN_TYPE);
		this.remoteAddress = request.getRemoteAddr();

		HttpSession session = request.getSession(false);
		this.sessionId = (session != null) ? session.getId() : null;
		StringBuilder builder = new StringBuilder();
		if (remoteAddress!=null) {
			builder.append("remoteAddress=").append(remoteAddress);
		}
		if (builder.length()>1) {
			builder.append(", ");
		}
		if (sessionId!=null) {
			builder.append("sessionId=<SESSION>");
			if (builder.length()>1) {
				builder.append(", ");
			}
		}
		if (tokenType!=null) {
			builder.append("tokenType=").append(this.tokenType);
		}
		if (tokenValue!=null) {
			builder.append("tokenValue=<TOKEN>");
		}
		this.display = builder.toString();
	}

	/**
	 * The access token value used to authenticate the request (normally in an authorization header).
	 * 
	 * @return the tokenValue used to authenticate the request
	 */
	public String getTokenValue() {
		return tokenValue;
	}
	
	/**
	 * The access token type used to authenticate the request (normally in an authorization header).
	 * 
	 * @return the tokenType used to authenticate the request if known
	 */
	public String getTokenType() {
		return tokenType;
	}

	/**
	 * Indicates the TCP/IP address the authentication request was received from.
	 * 
	 * @return the address
	 */
	public String getRemoteAddress() {
		return remoteAddress;
	}

	/**
	 * Indicates the <code>HttpSession</code> id the authentication request was received from.
	 * 
	 * @return the session ID
	 */
	public String getSessionId() {
		return sessionId;
	}

	/**
	 * The authentication details obtained by decoding the access token
	 * if available.
	 * 
	 * @return the decodedDetails if available (default null)
	 */
	public Object getDecodedDetails() {
		return decodedDetails;
	}

	/**
	 * The authentication details obtained by decoding the access token
	 * if available.
	 * 
	 * @param decodedDetails the decodedDetails to set
	 */
	public void setDecodedDetails(Object decodedDetails) {
		this.decodedDetails = decodedDetails;
	}

	@Override
	public String toString() {
		return display;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((sessionId == null) ? 0 : sessionId.hashCode());
		result = prime * result + ((tokenType == null) ? 0 : tokenType.hashCode());
		result = prime * result + ((tokenValue == null) ? 0 : tokenValue.hashCode());
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
		OAuth2AuthenticationDetails other = (OAuth2AuthenticationDetails) obj;
		if (sessionId == null) {
			if (other.sessionId != null)
				return false;
		}
		else if (!sessionId.equals(other.sessionId))
			return false;
		if (tokenType == null) {
			if (other.tokenType != null)
				return false;
		}
		else if (!tokenType.equals(other.tokenType))
			return false;
		if (tokenValue == null) {
			if (other.tokenValue != null)
				return false;
		}
		else if (!tokenValue.equals(other.tokenValue))
			return false;
		return true;
	}
	
	

}
