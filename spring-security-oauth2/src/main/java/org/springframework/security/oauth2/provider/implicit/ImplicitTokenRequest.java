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

package org.springframework.security.oauth2.provider.implicit;

import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * @author Dave Syer
 * 
 * @since 2.0.2
 *
 */
@SuppressWarnings("serial")
public class ImplicitTokenRequest extends TokenRequest {

	private OAuth2Request oauth2Request;

	public ImplicitTokenRequest(TokenRequest tokenRequest, OAuth2Request oauth2Request) {
		super(tokenRequest.getRequestParameters(), tokenRequest.getClientId(), tokenRequest.getScope(), tokenRequest.getGrantType());
		this.oauth2Request = oauth2Request;
	}

	public OAuth2Request getOAuth2Request() {
		return oauth2Request;
	}

}
