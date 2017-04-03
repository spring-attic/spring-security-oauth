package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a token has been expired.
 *
 * @author Evgeny Mironenko
 */
@SuppressWarnings("serial")
public class ExpiredTokenException extends InvalidTokenException {

    public ExpiredTokenException(String msg) {
        super(msg);
    }
}
