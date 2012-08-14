/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.common.signature;

import java.beans.PropertyEditorSupport;

/**
 * A signature secret that consists of a consumer secret and a tokent secret.
 * 
 * @author Ryan Heaton
 */
public class SignatureSecretEditor extends PropertyEditorSupport {

	public void setAsText(String text) throws IllegalArgumentException {
		super.setValue(new SharedConsumerSecretImpl(text));
	}
}
