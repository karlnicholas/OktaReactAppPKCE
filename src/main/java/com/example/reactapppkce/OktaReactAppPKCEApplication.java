package com.example.reactapppkce;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.jwt.Jwt;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@SpringBootApplication
@Configuration
@RestController
@RequestMapping
public class OktaReactAppPKCEApplication {

    public static void main(String[] args) {
        SpringApplication.run(OktaReactAppPKCEApplication.class, args);
    }
    private final ObjectMapper objectMapper;

    public OktaReactAppPKCEApplication(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:8080")
                        .allowedHeaders("Authorization", "Cache-Control", "Content-Type")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "PUT", "OPTIONS", "PATCH", "DELETE")
                        .allowCredentials(true)
                        .exposedHeaders("Authorization");
            }
        };
    }

    @GetMapping(value="/api/messages")
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // only return the claims if this token has the "email" scope
        if (hasScope("email", (Jwt) request.getAttribute("accessToken"))) {
            respondWithMessages(response);
        } else {
            response.sendError(403, "Unauthorized");
        }
    }
    private boolean hasScope(String scope, Jwt accessToken) {
        if (accessToken != null) {
            List<String> scopes = (List<String>) accessToken.getClaims().get("scp");
            return scopes != null && scopes.contains(scope);
        }
        return false;
    }

    private void respondWithMessages(HttpServletResponse response) throws IOException {
        Map<String, Object> messages = new HashMap<>();
        messages.put("messages", Arrays.asList(
                new Message("I am a robot."),
                new Message("Hello, world!")
        ));

        response.setStatus(200);
        response.addHeader("Content-Type", "application/json");
        objectMapper.writeValue(response.getOutputStream(), messages);
    }

    class Message {
        public Date date = new Date();
        public String text;

        Message(String text) {
            this.text = text;
        }
    }

/*
    @GetMapping(value="/login")
    public void handleLogin(HttpServletResponse httpServletResponse) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte[] bytes = verifier.getBytes("US-ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        String challenge = Base64.encodeBase64URLSafeString(digest);

        System.out.println(challenge);
        MultiValueMap<String, String> bodyPair = new LinkedMultiValueMap();
        bodyPair.add("code_challenge", challenge);
        bodyPair.add("response_type", "code");
        bodyPair.add("code_challenge_method", "S256");
        bodyPair.add("client_id", client_id);
        bodyPair.add("redirect_uri", redirect_uri);
        bodyPair.add("scope", "openid");
        bodyPair.add("state", "DSTATE");

        UriComponents uriComponents = UriComponentsBuilder.newInstance()
                .scheme("https").host("dev-1999209.okta.com")
                .path("/oauth2/default/v1/authorize")
                .queryParams(bodyPair).build();
        httpServletResponse.setHeader("Location", uriComponents.toUri().toString());
//        httpServletResponse.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
//        httpServletResponse.setHeader("Access-Control-Allow-Credentials", "true");
//        httpServletResponse.setHeader("origin", "http://localhost:8080");
        httpServletResponse.setStatus(302);
    }

    @GetMapping(value="/login/callback")
    public ResponseEntity<String> handleAuthorizationcodeCallback(ServletRequest request) throws JsonProcessingException {
        MultiValueMap<String, String> bodyPair = new LinkedMultiValueMap();
        bodyPair.add("client_id", "0oa2gfu3q64bv8qN85d7");
        bodyPair.add("code_verifier", verifier);
        bodyPair.add("redirect_uri", redirect_uri);
        bodyPair.add("grant_type", "authorization_code");
        bodyPair.add("code", request.getParameter("code"));
        //Set the headers you need send
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(bodyPair ,headers);
        ResponseEntity<String> response = restTemplate.postForEntity("/oauth2/default/v1/token", entity, String.class);
//        JsonNode tree = objectMapper.readTree(response.getBody());
//        String token = tree.path("access_token").asText();
//        return new RedirectView("/");
        return response;
    }
*/
}
