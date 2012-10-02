package org.springframework.security.oauth2.provider.endpoint;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.HashSet;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * @author Igor von Nyssen
 */
public class TestDefaultScopeValidator {
	private DefaultScopeValidator classUnderTest;

	private HashMap<String, String> parameters;

	private HashSet<String> validScopes;

	private ClientDetails mockClientDetails;

	@Before
	public void setup() {
		classUnderTest = new DefaultScopeValidator();
		mockClientDetails = mock(ClientDetails.class);
		validScopes = new HashSet<String>();
		validScopes.add("valid1");
		validScopes.add("valid2");
		when(mockClientDetails.getScope()).thenReturn(validScopes);
		when(mockClientDetails.isScoped()).thenReturn(true);
	}

	@Test
	public void testValidateParametersValidParameters() {
		parameters = new HashMap<String, String>();
		parameters.put("scope", "valid1,valid2");
		classUnderTest.validateParameters(parameters, mockClientDetails);
	}

	@Test
	public void testValidateParametersNoScopes() {
		parameters = new HashMap<String, String>();
		parameters.put("not_scope", "valid1 valid2");
		classUnderTest.validateParameters(parameters, mockClientDetails);
	}

	@Test
	public void testValidateParametersNotScoped() {
		parameters = new HashMap<String, String>();
		parameters.put("scope", "valid1,valid2");
		when(mockClientDetails.isScoped()).thenReturn(false);
		classUnderTest.validateParameters(parameters, mockClientDetails);
	}

	@Test
	public void testValidateParametersInvalidParameters() {
		parameters = new HashMap<String, String>();
		parameters.put("scope", "not_valid,valid2");
		try {
			classUnderTest.validateParameters(parameters, mockClientDetails);
		}
		catch (InvalidScopeException e) {
			// check that message does not contain additional scopes or other information
			assertEquals("Invalid scope: not_valid", e.getMessage());
		}
	}

}
