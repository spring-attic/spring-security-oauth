/*
 * Copyright 2006-2010 the original author or authors.
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
package org.springframework.security.oauth2.client.test;

import org.springframework.web.client.RestOperations;

/**
 * Marker interface for an object that has a getter and setter for a {@link RestOperations}.
 * 
 * @author Dave Syer
 * 
 */
public interface RestTemplateHolder {

	void setRestTemplate(RestOperations restTemplate);

	RestOperations getRestTemplate();

}
