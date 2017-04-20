package demo;

import org.springframework.test.context.ContextConfiguration;

import sparklr.common.AbstractRefreshTokenSupportTests;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@ContextConfiguration(classes=Application.class)
public class RefreshTokenSupportTests extends AbstractRefreshTokenSupportTests {
	protected String getPassword() {
		return "secret";
	}

	protected String getUsername() {
		return "dave";
	}
}
