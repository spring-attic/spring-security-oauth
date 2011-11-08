package org.springframework.security.oauth.examples.tonr.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.examples.tonr.SparklrException;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.http.OAuth2AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.service.OAuth2ClientTokenServices;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.web.client.RestOperations;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * @author Ryan Heaton
 */
public class SparklrServiceImpl implements SparklrService {

	private String sparklrPhotoListURL;
	private String sparklrTrustedMessageURL;
	private String sparklrPhotoURLPattern;
	// TODO: this should be a RestOperations
	private OAuth2RestTemplate sparklrRestTemplate;
	private RestOperations trustedClientRestTemplate;
	private OAuth2ClientTokenServices tokenServices;

	public List<String> getSparklrPhotoIds() throws SparklrException {
		try {
			InputStream photosXML = new ByteArrayInputStream(sparklrRestTemplate.getForObject(
					URI.create(sparklrPhotoListURL), byte[].class));

			final List<String> photoIds = new ArrayList<String>();
			SAXParserFactory parserFactory = SAXParserFactory.newInstance();
			parserFactory.setValidating(false);
			parserFactory.setXIncludeAware(false);
			parserFactory.setNamespaceAware(false);
			SAXParser parser = parserFactory.newSAXParser();
			parser.parse(photosXML, new DefaultHandler() {
				@Override
				public void startElement(String uri, String localName, String qName, Attributes attributes)
						throws SAXException {
					if ("photo".equals(qName)) {
						photoIds.add(attributes.getValue("id"));
					}
				}
			});
			return photoIds;
		} catch (InvalidTokenException badToken) {
			// we've got a bad token, probably because it's expired.
			OAuth2ProtectedResourceDetails resource = sparklrRestTemplate.getResource();
			OAuth2ClientContext context = OAuth2ClientContextHolder.getContext();
			if (context != null) {
				// TODO: this one is kind of a hack for this application
				// the problem is that the sparklr photos page doesn't remove the 'code=' request parameter.
				// ((OAuth2ClientContextImpl) context).setAuthorizationCode(null);
			}
			// clear any stored access tokens...
			tokenServices.removeToken(SecurityContextHolder.getContext().getAuthentication(), resource);
			// go get a new access token...
			throw new OAuth2AccessTokenRequiredException(resource);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} catch (SAXException e) {
			throw new IllegalStateException(e);
		} catch (ParserConfigurationException e) {
			throw new IllegalStateException(e);
		}
	}

	public InputStream loadSparklrPhoto(String id) throws SparklrException {
		return new ByteArrayInputStream(sparklrRestTemplate.getForObject(
				URI.create(String.format(sparklrPhotoURLPattern, id)), byte[].class));
	}

	public String getTrustedMessage() {
		return this.trustedClientRestTemplate.getForObject(URI.create(sparklrTrustedMessageURL), String.class);
	}

	public void setSparklrPhotoURLPattern(String sparklrPhotoURLPattern) {
		this.sparklrPhotoURLPattern = sparklrPhotoURLPattern;
	}

	public void setSparklrPhotoListURL(String sparklrPhotoListURL) {
		this.sparklrPhotoListURL = sparklrPhotoListURL;
	}
	
	public void setSparklrTrustedMessageURL(String sparklrTrustedMessageURL) {
		this.sparklrTrustedMessageURL = sparklrTrustedMessageURL;
	}

	public void setSparklrRestTemplate(OAuth2RestTemplate sparklrRestTemplate) {
		this.sparklrRestTemplate = sparklrRestTemplate;
	}

	public void setTrustedClientRestTemplate(RestOperations trustedClientRestTemplate) {
		this.trustedClientRestTemplate = trustedClientRestTemplate;
	}

	public void setTokenServices(OAuth2ClientTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}
}
