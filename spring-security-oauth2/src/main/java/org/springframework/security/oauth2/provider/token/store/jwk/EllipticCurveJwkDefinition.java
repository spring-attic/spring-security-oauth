package org.springframework.security.oauth2.provider.token.store.jwk;

/**
 * A JSON Web Key (JWK) representation of an Elliptic Curve key.
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518#page-28">JSON Web Algorithms (JWA)</a>
 *
 * @author Michael Duergner <michael@sprucehill.io>
 */
final class EllipticCurveJwkDefinition extends JwkDefinition {

    private final String x;

    private final String y;

    private final String curve;

    /**
     * Creates an instance of an Elliptic Curve JSON Web Key (JWK).
     *
     * @param keyId        the Key ID
     * @param publicKeyUse the intended use of the Public Key
     * @param algorithm    the algorithm intended to be used
     * @param x            the x value to be used
     * @param y            the y value to be used
     * @param curve        the curve to be used
     */
    EllipticCurveJwkDefinition(String keyId,
                                         PublicKeyUse publicKeyUse,
                                         CryptoAlgorithm algorithm,
                                         String x,
                                         String y,
                                         String curve) {
        super(keyId, KeyType.EC, publicKeyUse, algorithm);
        this.x = x;
        this.y = y;
        this.curve = curve;
    }

    String getX() {
        return x;
    }

    String getY() {
        return y;
    }

    String getCurve() {
        return curve;
    }
}
