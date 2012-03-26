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
package org.springframework.security.oauth2.provider.error;

import org.springframework.http.HttpEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Strategy for rendering a {@link OAuth2Exception} in cases where they cannot be rendered by the Spring dispatcher
 * servlet (i.e. usually in a filter chain).
 * 
 * @author Dave Syer
 * 
 */
public interface OAuth2ExceptionRenderer {
	void handleHttpEntityResponse(HttpEntity<?> responseEntity, ServletWebRequest webRequest) throws Exception;
}
