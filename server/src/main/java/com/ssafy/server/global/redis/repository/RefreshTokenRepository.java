package com.ssafy.server.global.redis.repository;

import com.ssafy.server.global.redis.token.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}