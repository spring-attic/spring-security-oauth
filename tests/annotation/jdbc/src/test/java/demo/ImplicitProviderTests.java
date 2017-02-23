package demo;

import org.springframework.test.context.ContextConfiguration;

import sparklr.common.AbstractImplicitProviderTests;

/**
 * @author Dave Syer
 */
@ContextConfiguration(classes=Application.class)
public class ImplicitProviderTests extends AbstractImplicitProviderTests {

	protected String getPassword() {
		return "secret";
	}

	protected String getUsername() {
		return "dave";
	}
	
}
