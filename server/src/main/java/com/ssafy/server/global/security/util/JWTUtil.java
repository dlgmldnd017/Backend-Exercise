package com.ssafy.server.global.security.util;

import com.ssafy.server.domain.user.entity.User;
import com.ssafy.server.domain.user.repository.UserRepository;
import com.ssafy.server.domain.user.service.CustomUserDetailsService;
import com.ssafy.server.global.security.dto.TokenDTO;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Component
public class JWTUtil {
    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;
    private SecretKey secretKey;
    private final static long ACCESS_TOKEN_VALIDITY_SECONDS = 30;
    private final static long REFRESH_TOKEN_VALIDITY_SECONDS = 86400;
    private final CustomUserDetailsService userDetailsService;

    public JWTUtil(RedisTemplate<String, String> redisTemplate, @Value("${spring.jwt.secret}") String secret,
                   CustomUserDetailsService userDetailsService, UserRepository userRepository) {
        this.redisTemplate = redisTemplate;
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
    }

    /**
     * 로그인 시 Access와 Refresh 저장하는 메서드
     *
     * @param email
     * @return Access와 Refresh 토큰
     */
    public TokenDTO generateToken(String email) {
        // Access Token 생성
        String accessToken = Jwts.builder()
                .claim("email", email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_SECONDS * 1000))
                .signWith(secretKey)
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .claim("email", email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY_SECONDS * 1000))
                .signWith(secretKey)
                .compact();

        // redis에 저장
//        redisTemplate.opsForValue().set(
//                email,
//                refreshToken,
//                REFRESH_TOKEN_VALIDITY_SECONDS,
//                TimeUnit.MILLISECONDS
//        );
        return new TokenDTO(accessToken, refreshToken);
    }

    /**
     * Access 토큰 만료될 경우
     *
     * @param email
     * @return Access 토큰
     */
    public String generateAccessToken(String email) {
        // Access Token 생성
        String accessToken = Jwts.builder()
                .claim("email", email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_SECONDS * 1000))
                .signWith(secretKey)
                .compact();

        return accessToken;
    }

    /**
     * 토큰 유효성 체크
     *
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            System.out.println("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            System.out.println("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            System.out.println("지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            System.out.println("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    public String getUserEmail(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload()
                .get("email", String.class);
    }

    public User getUserFromToken(String token) throws IOException {
        String email = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload()
                .get("email", String.class);
        return userRepository.findByEmail(email);
    }

    public Authentication getAuthentication(String token) {
        String email = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload()
                .get("email", String.class);

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        return new UsernamePasswordAuthenticationToken(userDetails, "", null);
    }
}