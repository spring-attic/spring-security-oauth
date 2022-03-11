package org.springframework.security.oauth2.client;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class DefaultOAuth2ClientContextTests {

    @Test
    public void resetsState() {
        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext();
        clientContext.setPreservedState("state1", "some-state-1");
        clientContext.setPreservedState("state2", "some-state-2");
        clientContext.setPreservedState("state3", "some-state-3");
        assertNull(clientContext.removePreservedState("state1"));
        assertNull(clientContext.removePreservedState("state2"));
        assertEquals("some-state-3", clientContext.removePreservedState("state3"));
    }

}