package coin.ethereum;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bitcoinj.core.Address;
import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.HashUtil;
import org.spongycastle.util.encoders.Hex;

public class MainBackup {

    /**
     * Log
     */
    private static final Logger log = LogManager.getLogger(Main.class.getName());

    private static final int CHECKSUM_SIZE              = 4;
    private static final byte[] PUBLIC_PRFIX_WALLET     = {(byte)0x00};
    private static final byte[] PRIVATE_PRFIX_WALLET    = {(byte)0x80};

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        /*
        //String senderPrivKey = "";
        byte[] senderPrivKey = HashUtil.sha3("cow".getBytes());
        String spk = Hex.encode(senderPrivKey).toString();

        BigInteger pk = new BigInteger(spk, 16);

        log.info("Private key: " + pk.toString(16));

        ECKey key = ECKey.fromPrivate(pk);
        log.info("Public key: " + Hex.toHexString(key.getAddress()));
        */
        //String privateECDSAKey  = "";
        //getKeyPair(privateECDSAKey);
        //log.info(kp.getPublic().toString());
        //log.info(kp.getPrivate().toString());


        /*
        String publicECDSAKey   = "";
        String privateECDSAKey  = "";
        log.info("------------------------------------------------------------------------------");
        log.info("[base58] public key  : " + getBitcoinBase58PublicKey(publicECDSAKey));
        log.info("[base58] private key : " + getBitcoinBase58PrivateKey(privateECDSAKey));
        log.info("------------------------------------------------------------------------------");
        */

        //getBitcoinBase58PrivateKey("0");

        // create a new EC Key ...
        ECKey key = new ECKey();

        log.info("Private key: " + Hex.toHexString(key.getPrivKeyBytes()));
        log.info("Public key: " + Hex.toHexString(key.getAddress()));

        //Address targetAddress = new Address(MainNetParams.get(), "1RbxbA1yP2Lebauuef3cBiBho853f7jxs");
        //log.info(targetAddress);
    }

    /**
     * Public key to wallet import format
     *
     * @param publicECDSAKey - public ECDSA key
     */
    private static String getBitcoinBase58PublicKey(String publicECDSAKey) {

        try {

            byte[] n = concatenateByteArrays(PUBLIC_PRFIX_WALLET,Ripemd160.getHash(hash256(hexToBytes(publicECDSAKey))));
            return Base58Check.encodePlain(
                    concatenateByteArrays(
                            n,
                            Arrays.copyOfRange(hash256(hash256(n)),0,CHECKSUM_SIZE)
                    )
            );

            /* byte[] _p = {(byte)0x00};
            byte[] p = hexToBytes(publicECDSAKey);
            byte[] h = hash256(p);
            byte[] r = Ripemd160.getHash(h);
            byte[] n = concatenateByteArrays(_p,r);
            byte[] s1 = hash256(n);
            byte[] s2 = hash256(s1);
            byte[] c = Arrays.copyOfRange(s2,0,4);
            byte[] t = concatenateByteArrays(n,c);

            log.info("========= Generate wallet BitCoin public key =========");
            log.info("[ECDSA] public key  : " + bytesToHex(p));
            log.info("hash[ECDSA key]     : " + bytesToHex(h));
            log.info("ripemd[hash]        : " + bytesToHex(r));
            log.info("prefix[ripemd]      : " + bytesToHex(n));
            log.info("hash1[prefix]       : " + bytesToHex(s1));
            log.info("hash2[hash1]        : " + bytesToHex(s2));
            log.info("checksum[hash2]     : " + bytesToHex(c));
            log.info("cc[hash+checksum]   : " + bytesToHex(t));
            log.info("-------------------------------------------------------");
            log.info("[base58] public key : " + Base58Check.encodePlain(t));
            log.info("-------------------------------------------------------");
            log.info("");*/

        } catch (Exception e) {
            log.error(e);
        }

        return "";
    }

    /**
     * Private key to wallet import format
     *
     * @param privateECDSAKey - private ECDSA key
     */
    private static String getBitcoinBase58PrivateKey(String privateECDSAKey) {

        try {

            byte[] e = concatenateByteArrays(PRIVATE_PRFIX_WALLET,hexToBytes(privateECDSAKey));
            return Base58Check.encodePlain(
                    concatenateByteArrays(
                            e,
                            Arrays.copyOfRange(hash256(hash256(e)),0,CHECKSUM_SIZE)
                    )
            );

            /*byte[] _p = {(byte)0x80};
            //byte[] bPrivateKey = hash256(passphrase.getBytes(StandardCharsets.UTF_8));
            byte[] p = hexToBytes(privateECDSAKey);
            byte[] e = concatenateByteArrays(_p,p);
            byte[] h1 = hash256(e);
            byte[] h2 = hash256(h1);
            byte[] c = Arrays.copyOfRange(h2,0,CHECKSUM_SIZE);
            byte[] t = concatenateByteArrays(e,c);

            log.info("========= Generate wallet BitCoin private key =========");
            log.info("[ECDSA] private key  : " + bytesToHex(p));
            log.info("prefix[ECDSA key]    : " + bytesToHex(e));
            log.info("hash1[prefix]        : " + bytesToHex(h1));
            log.info("hash2[hash1]         : " + bytesToHex(h2));
            log.info("checksum[hash2]      : " + bytesToHex(c));
            log.info("cc[prefix+checksum]  : " + bytesToHex(t));
            log.info("-------------------------------------------------------");
            log.info("[base58] private key : " + Base58Check.encodePlain(t));
            log.info("-------------------------------------------------------");*/

        } catch (Exception e) {
            log.error(e);
        }

        return "";
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] hash256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data);

        return md.digest();
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Generate New ECDSA Key

        KeyPair userKey = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            generator.initialize(ecSpec, new SecureRandom());
            userKey = generator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return userKey;
    }

    private static void getKeyPair(String pKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        byte[] encoded = pKey.getBytes(StandardCharsets.UTF_8);
        //byte[] encoded = hexToBytes(pKey);

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(pKey), ecSpec);

        // If key is private, use PKCS
        PKCS8EncodedKeySpec fPrivate = new PKCS8EncodedKeySpec(encoded);

        // If key is public, use X.509
        X509EncodedKeySpec fPublic = new X509EncodedKeySpec(encoded);

        // Retrieve key using KeyFactory
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        PublicKey publicKey = kf.generatePublic(privateKeySpec);
        log.info(publicKey);

        //PublicKey publicKey = kf.generatePublic(fPublic);
        //PrivateKey privateKey = kf.generatePrivate(fPrivate);

        //return new KeyPair(publicKey,privateKey);
    }
}