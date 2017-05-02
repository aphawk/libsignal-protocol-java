package demo;


import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * @Author Vincent
 */
public class ECSignedPublicKey {
    private final ECPublicKey publicKey;
    private final byte[] signature;

    public ECSignedPublicKey(ECPublicKey publicKey, byte[] signature) {
        this.publicKey = publicKey;
        this.signature = signature;
    }

    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }

    public byte[] getSignature() {
        return this.signature;
    }
}
