package pl.gregorymartin.jwtappclient;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.Stream;


@Controller
class BookApiClient {
    public BookApiClient() {
        RsaUtil rsaUtil = new RsaUtil();

        KeyPair keyPair = rsaUtil.readFilePrivateKey("keys/private_key.ppk");

        String token = JwtTokenService.createToken(keyPair);

        addBooks(token);
        getBooks(token);
    }

    private void addBooks(String token) {

        MultiValueMap<String,String> headers = new HttpHeaders();
        headers.add("Authorization","Bearer " + token);
        String bookToAdd = "Book3 +";
        HttpEntity httpEntity = new HttpEntity(bookToAdd,headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> exchange = restTemplate.exchange("http://localhost:8080/api/books",
                HttpMethod.POST,
                httpEntity,
                String.class);

    }

    private void getBooks(String token) {

        MultiValueMap<String,String> headers = new HttpHeaders();
        headers.add("Authorization","Bearer " + token);

        HttpEntity httpEntity = new HttpEntity(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String[]> exchange = restTemplate.exchange("http://localhost:8080/api/books",
                HttpMethod.GET,
                httpEntity,
                String[].class);

        Stream.of(exchange.getBody()).forEach(System.out::println);
    }
}
