package pl.gregorymartin.jwtappclient;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

public class RsaUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
/*

    public static RSAPublicKey getPublic(File keyFile){
        try {
            PEMParser pemParser = new PEMParser(new FileReader(keyFile));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object object = pemParser.readObject();
            PublicKey kp = converter.getPublicKey((SubjectPublicKeyInfo) object);

            return (RSAPublicKey)kp;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
*/


    protected static KeyPair readKeyPair(File keyFile) {

        try {
            PEMParser pemParser = new PEMParser(new FileReader(keyFile));
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object object = pemParser.readObject();
            KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
            return kp;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
/*    public RSAPublicKey readFilePublicKey(String filename) {
        return RsaUtil.getPublic(readFile(filename));
    }*/

    public KeyPair readFilePrivateKey(String filename) {
        return RsaUtil.readKeyPair(readFile(filename));
    }

    private File readFile(String fileName) {
        ClassLoader classLoader = getClass().getClassLoader();
        return new File(classLoader.getResource(fileName).getFile());
    }
}
