package com.jobexecution.service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${app.security.jwt.secretKey}")
    private String secretKey;
    @Value("${app.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${app.security.jwt.refreshToken.expiration}")
    private long refreshExpiration;


    public String extractUserName(String jwtToken){
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public <T>T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails, jwtExpiration);
    }
    public String generateRefreshToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails, refreshExpiration);
    }
    private String generateToken(Map<String, Object> extraClaim, UserDetails userDetails, long expiration){
        return Jwts.builder()
                .setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSingInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public boolean validateToken(String token, UserDetails userDetails){
        String userName = extractUserName(token);
        if(!userDetails.isAccountNonLocked()){
            throw new LockedException("User account is locked");
        }
        if(!userDetails.isEnabled()){
            throw new DisabledException("User account is disabled");
        }
        if(!userDetails.isCredentialsNonExpired()){
            throw new CredentialsExpiredException("User credentials has expired");
        }
        if(!userDetails.isAccountNonExpired()){
            throw new AccountExpiredException("User account has expired");
        }
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSingInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSingInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

