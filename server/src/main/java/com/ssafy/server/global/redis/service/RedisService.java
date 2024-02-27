package com.ssafy.server.global.redis.service;

import com.ssafy.server.global.redis.repository.RefreshTokenRepository;
import com.ssafy.server.global.redis.token.RefreshToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    /**
     * redis에 refresh 토큰 저장
     *
     * @param refreshToken
     * @param email
     */
    public void saveToken(String email, String refreshToken) {
        RefreshToken token = new RefreshToken(email, refreshToken);
        refreshTokenRepository.save(token);
    }

    /**
     * redis 키가 존재하는지 확인
     *
     * @param key
     * @return
     */
    public boolean keyExists(String key) {
        return redisTemplate.hasKey(key);
    }

    /**
     * 로그아웃 수행시 해당 키 삭제
     *
     * @param key
     */
    public void deleteToken(String key) {
        redisTemplate.delete(key);
    }
}