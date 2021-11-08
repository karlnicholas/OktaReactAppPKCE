package com.example.reactapppkce;

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AccessTokenVerifier verifier;

    public JwtAuthenticationFilter() {
        verifier = JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer("https://dev-1999209.okta.com/oauth2/default") // https://{yourOktaDomain}/oauth2/default
                .build();
    }
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws IOException, ServletException {

        String authorizationHeader = httpServletRequest.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                Jwt token = verifier.decode(authorizationHeader.replace("Bearer ", ""));
                httpServletRequest.setAttribute("accessToken", token);
            } catch (JwtVerificationException e) {
                e.printStackTrace();
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}