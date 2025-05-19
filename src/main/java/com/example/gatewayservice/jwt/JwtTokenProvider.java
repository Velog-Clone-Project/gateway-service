package com.example.gatewayservice.jwt;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private final JwtKeyProperties jwtKeyProperties;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Autowired
    public JwtTokenProvider(JwtKeyProperties jwtKeyProperties) {
        this.jwtKeyProperties = jwtKeyProperties;
    }

    // 테스트용 생성자
    public JwtTokenProvider(JwtKeyProperties keyProperties, long accessTokenExp, long refreshTokenExp) {
        this.jwtKeyProperties = keyProperties;
        this.accessTokenExpiration = accessTokenExp;
        this.refreshTokenExpiration = refreshTokenExp;
    }

    public PublicKey getPublicKey() {
        return jwtKeyProperties.getPublicKey();
    }


    public boolean validateToken(String token) {
        try {
            // 토큰 파싱 및 서명 검증
            Claims claims = Jwts.parser()
//                    .verifyWith(secretKey)
                    .verifyWith(getPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // 만료 여부 확인
            return !claims.getExpiration().before(new Date());
        } catch (SecurityException | MalformedJwtException e) {
            throw new SecurityException(e.getMessage());
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException(e.getHeader(), e.getClaims(), e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException(e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public String getUserId(String token) {
        return Jwts.parser()
//                .verifyWith(secretKey)
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
