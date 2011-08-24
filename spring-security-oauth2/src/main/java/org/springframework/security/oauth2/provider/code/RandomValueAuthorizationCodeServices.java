package org.springframework.security.oauth2.provider.code;

import java.security.SecureRandom;
import java.util.Random;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Base implementation for authorization code services that generates a random-value authorization code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class RandomValueAuthorizationCodeServices implements AuthorizationCodeServices, InitializingBean {

	private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			.toCharArray();

	private Random random;
	private int codeLengthBytes = 6;

	public void afterPropertiesSet() throws Exception {
		if (getRandom() == null) {
			setRandom(new SecureRandom());
		}
	}

	protected abstract void store(String code,
			OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> authentication);

	protected abstract OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> remove(String code);

	public String createAuthorizationCode(
			OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> authentication) {
		String code = createAuthorizationCode();
		store(code, authentication);
		return code;
	}

	public OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> consumeAuthorizationCode(String code)
			throws InvalidGrantException {
		OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken> auth = this.remove(code);
		if (auth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + code);
		}
		return auth;
	}

	protected String createAuthorizationCode() {
		byte[] verifierBytes = new byte[getCodeLengthBytes()];
		getRandom().nextBytes(verifierBytes);
		return getAuthorizationCodeString(verifierBytes);
	}

	/**
	 * Convert these random bytes to a verifier string. The length of the byte array can be
	 * {@link #setCodeLengthBytes(int) configured}. Default implementation mods the bytes to fit into the ASCII letters
	 * 1-9, A-Z, a-z .
	 * 
	 * @param verifierBytes The bytes.
	 * @return The string.
	 */
	protected String getAuthorizationCodeString(byte[] verifierBytes) {
		char[] chars = new char[verifierBytes.length];
		for (int i = 0; i < verifierBytes.length; i++) {
			chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
		}
		return new String(chars);
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @return The random value generator used to create token secrets.
	 */
	public Random getRandom() {
		return random;
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @param random The random value generator used to create token secrets.
	 */
	public void setRandom(Random random) {
		this.random = random;
	}

	/**
	 * The verifier length in bytes, before being encoded to a string.
	 * 
	 * @return The verifier length in bytes, before being encoded to a string.
	 */
	public int getCodeLengthBytes() {
		return codeLengthBytes;
	}

	/**
	 * The verifier length in bytes, before being encoded to a string.
	 * 
	 * @param codeLengthBytes The verifier length in bytes, before being encoded to a string.
	 */
	public void setCodeLengthBytes(int codeLengthBytes) {
		this.codeLengthBytes = codeLengthBytes;
	}

}
