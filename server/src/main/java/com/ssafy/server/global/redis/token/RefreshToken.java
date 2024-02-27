package com.ssafy.server.global.redis.token;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash("token")
public class RefreshToken {

    @Id
    private String email;
    private String refreshToken;


    public RefreshToken(String email, String refreshToken) {
        this.email = email;
        this.refreshToken = refreshToken;
    }
}