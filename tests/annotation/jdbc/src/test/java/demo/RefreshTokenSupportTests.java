package demo;

import org.springframework.boot.test.SpringApplicationConfiguration;

import sparklr.common.AbstractRefreshTokenSupportTests;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class RefreshTokenSupportTests extends AbstractRefreshTokenSupportTests {
	protected String getPassword() {
		return "secret";
	}

	protected String getUsername() {
		return "dave";
	}
}
