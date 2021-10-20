/*
 * Copyright 2006-2019 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth.common.signature.RSAKeySecret;
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl;
import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.oauth.provider.BaseConsumerDetails;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Dave Syer
 * 
 */
@Deprecated
public class ConsumerDetailsFactoryBean implements FactoryBean<ConsumerDetails>, ResourceLoaderAware {
	
	private static final Log logger = LogFactory.getLog(ConsumerDetailsFactoryBean.class);
	private Object typeOfSecret;
	private BaseConsumerDetails consumer = new BaseConsumerDetails();
	private String secret;
	private ResourceLoader resourceLoader;
	
	public void setResourceLoader(ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}
	
	public void setSecret(String secret) {
		this.secret = secret;
	}

	public void setConsumerKey(String consumerKey) {
		consumer.setConsumerKey(consumerKey);
	}

	public void setConsumerName(String consumerName) {
		consumer.setConsumerName(consumerName);
	}

	public void setSignatureSecret(SignatureSecret signatureSecret) {
		consumer.setSignatureSecret(signatureSecret);
	}

	public void setAuthorities(String authorities) {
		consumer.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
	}

	public void setResourceName(String resourceName) {
		consumer.setResourceName(resourceName);
	}

	public void setResourceDescription(String resourceDescription) {
		consumer.setResourceDescription(resourceDescription);
	}

	public void setRequiredToObtainAuthenticatedToken(boolean requiredToObtainAuthenticatedToken) {
		consumer.setRequiredToObtainAuthenticatedToken(requiredToObtainAuthenticatedToken);
	}

	public void setTypeOfSecret(Object typeOfSecret) {
		this.typeOfSecret = typeOfSecret;
	}

	public ConsumerDetails getObject() throws Exception {
		if ("rsa-cert".equals(typeOfSecret)) {
			InputStream inputStream = null;
			try {
				inputStream = resourceLoader.getResource(secret).getInputStream();
				Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
				consumer.setSignatureSecret(new RSAKeySecret(cert.getPublicKey()));
			}
			catch (IOException e) {
				throw new BeanCreationException("RSA certificate not found",
						e);
			}
			catch (CertificateException e) {
				throw new BeanCreationException("Invalid RSA certificate", e);
			}
			catch (NullPointerException e) {
				throw new BeanCreationException("Could not load RSA certificate", e);
			}
			finally {
				try {
					if (inputStream != null) {
						inputStream.close();
					}
				} 
				catch (IOException e) {
					logger.warn("Cannot close open stream: ", e);
				}
			}
		}
		else {
			consumer.setSignatureSecret(new SharedConsumerSecretImpl(secret));
		}
		return consumer;
	}

	public Class<?> getObjectType() {
		return BaseConsumerDetails.class;
	}

	public boolean isSingleton() {
		return true;
	}

}
