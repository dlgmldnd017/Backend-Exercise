package com.ssafy.server.domain.user.repository;

import com.ssafy.server.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
  Boolean existsByEmail(String email);

  // username을 받아 DB 테이블에서 회원을 조회하는 메소드 작성
  User findByEmail(String email);

  void deleteByEmail(String email);
}