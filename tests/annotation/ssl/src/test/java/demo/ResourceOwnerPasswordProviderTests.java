package demo;

import org.springframework.test.context.ContextConfiguration;

import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

/**
 * @author Dave Syer
 */
@ContextConfiguration(classes = Application.class)
public class ResourceOwnerPasswordProviderTests
		extends AbstractResourceOwnerPasswordProviderTests {

}
