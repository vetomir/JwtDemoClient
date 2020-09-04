package pl.gregorymartin.jwtappclient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Service
class JwtTokenService {

    public JwtTokenService() {

    }

    protected static String createToken(final KeyPair keyPair) {
        String token = null;
        try {
            Algorithm algorithm = Algorithm.RSA512(null, (RSAPrivateKey) keyPair.getPrivate());
            token = JWT.create()
                    .withClaim("name", "chuj")
                    .withClaim("admin", true)
                    .sign(algorithm);
        } catch (JWTCreationException x) {
            throw x;
        }
        return token;
    }
/*
    protected static boolean checkToken(final RSAPublicKey publicKey, final String token, User user) {
        try {
            Algorithm algorithm = Algorithm.RSA512(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("name", user.getName())
                    .withClaim("username", user.getUsername())
                    .withClaim("password", user.getPassword())
                    .withClaim("isAdmin", user.isAdmin())
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return true;

        } catch (JWTVerificationException x) {
            throw x;
        }
    }*/
}
