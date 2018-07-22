package coin.ethereum;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.*;

public class Main {

    /**
     * Log
     */
    private static final Logger log = LogManager.getLogger(Main.class.getName());

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {

        //Get secp256k1 pair - which we can use for both addresses
        ECKeyPair keyPair = ECKeyPair.createECKeyPair();
        log.info("Private key [" + keyPair.getPrivateKey().length() + "]: " + keyPair.getPrivateKey());
        log.info("Public key [" + keyPair.getPublicKey().length() + "]: " + keyPair.getPublicKey());

        //Calculate Bitcoin Address
        BtcAddressGen.genBitcoinAddress(keyPair.getPublicKey());

        //Calculate Ethereum Address
        EthAddressGen.genEthereumAddress(keyPair.getPublicKey());
    }

}