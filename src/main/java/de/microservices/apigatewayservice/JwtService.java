package de.microservices.apigatewayservice;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtService {
    @Autowired
    private Environment env;

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(env.getProperty("jwt.secret"));
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims parseClaims(String token) {
        try {
            Jws<Claims> parsedToken = Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token);

            return parsedToken.getBody();
        } catch (JwtException ex) {
            throw new IllegalArgumentException("Invalid JWT token", ex);
        }
    }

    public boolean isJwtValid(String jwt) {
        Claims claims = parseClaims(jwt);
        String subject = claims.getSubject();
        Date expiration = claims.getExpiration();

        return subject != null && !subject.isEmpty() && expiration != null && !expiration.before(new Date());
    }

    public String getUsernameFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.getSubject();
    }

    public List<String> getRolesFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.get("roles", List.class);
    }
}
