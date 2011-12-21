/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.security.oauth2.http.converter.jaxb;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public final class JaxbOAuth2ExceptionMessageConverter extends
		AbstractJaxbMessageConverter<JaxbOAuth2Exception, OAuth2Exception> {

	public JaxbOAuth2ExceptionMessageConverter() {
		super(JaxbOAuth2Exception.class, OAuth2Exception.class);
	}

	protected JaxbOAuth2Exception convertToInternal(OAuth2Exception exception) {
		JaxbOAuth2Exception result = new JaxbOAuth2Exception();
		result.setDescription(exception.getMessage());
		result.setErrorCode(exception.getOAuth2ErrorCode());
		return result;
	}

	protected OAuth2Exception convertToExternal(JaxbOAuth2Exception jaxbOAuth2Exception) {
		return OAuth2Exception.create(jaxbOAuth2Exception.getErrorCode(), jaxbOAuth2Exception.getDescription());
	}
}
