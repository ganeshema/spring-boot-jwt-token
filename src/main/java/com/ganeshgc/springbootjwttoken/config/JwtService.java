package com.ganeshgc.springbootjwttoken.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
     @Value("${jwt.secret}")
    private  String SECRET_KEY;
//========== below methods are to extract username from claims from the token which to be used in jwtauthenticationfilter==========
//========================================================================================================================================================================================================================
    public String extractUsername(String jwt) {
        return extractClaim(jwt, Claims::getSubject);
    }
    public <T> T extractClaim(String jwt, Function<Claims,T> claimsResolver) {
        final Claims claims=extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String jwt) {
        // This method is responsible for extracting all claims (information) from the given JWT token.
        // The 'Claims' object is essentially a map of key-value pairs that contains the data in the JWT, such as the subject (user info), expiration time, issuer, etc.

        return Jwts.parser()
                // Jwts.parser() creates a new instance of a JWT parser that will be used to decode the JWT token.
                // 'Jwts' is a utility class from the io.jsonwebtoken library that provides various methods for working with JWTs, including creating, signing, parsing, and validating tokens.

                .setSigningKey(getSigningKey())
                // This method sets the signing key, which is used to verify the JWT signature.
                // The signing key is essential because it ensures that the JWT was not tampered with. The 'getSigningKey()' method (not shown here) likely returns a secret key or public key that was used to sign the token.

                .build()
                // After setting the signing key, 'build()' finalizes the parser configuration, making it ready to parse the JWT.
                // It creates a JwtParser object that can now be used to parse and validate the token.

                .parseClaimsJws(jwt)
                // This method parses the JWT, specifically a JWS (JSON Web Signature), which includes the payload (claims) and the signature.
                // It checks the signature of the JWT using the signing key, ensuring that the JWT has not been modified and is valid.
                // If the JWT is valid, it proceeds to the next step. If it's invalid (e.g., if the signature doesn't match), an exception will be thrown.

                .getBody();
        // After the JWT is successfully parsed and verified, 'getBody()' extracts the body of the token, which is where the claims (information about the user, expiration date, issuer, etc.) are stored.
        // This body is returned as a 'Claims' object, which can be used to retrieve specific data from the token.
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //==========below methods are to generate token=========
//========================================================================================================================================================================================================================
    //this is to generate token just with userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails); // Call the overloaded method without extra claims
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .claims(extraClaims) // Set the extra claims if any
                .setSubject(userDetails.getUsername()) // Ensure the subject (username) is added
                .setIssuedAt(new Date(System.currentTimeMillis())) // Set the token's issued time
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Set token expiration (24 minutes)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Sign the token with the signing key and algorithm
                .compact(); // Compact the JWT to a URL-safe string
    }


    //==========below methods are to validate token============
    //========================================================================================================================================================================================================================
    public boolean isTokenValid(String token, UserDetails userDetails) { //we are passing userdetails because we want to validate this token belongs to this user or not
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
