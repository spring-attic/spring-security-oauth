package demo;

import org.springframework.boot.test.SpringApplicationConfiguration;

import sparklr.common.AbstractImplicitProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class ImplicitProviderTests extends AbstractImplicitProviderTests {

	protected String getPassword() {
		return "secret";
	}

	protected String getUsername() {
		return "dave";
	}
	
}
