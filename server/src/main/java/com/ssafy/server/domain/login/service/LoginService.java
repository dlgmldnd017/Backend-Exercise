package com.ssafy.server.domain.login.service;


import com.ssafy.server.domain.login.dto.LoginDto;
import com.ssafy.server.domain.user.dto.ProfileDto;
import com.ssafy.server.domain.user.entity.User;
import com.ssafy.server.domain.user.repository.UserRepository;
import com.ssafy.server.global.security.util.JWTUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.io.IOException;

@Service
public class LoginService {

    private final UserRepository repository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JWTUtil jwtUtil;

    public LoginService(UserRepository repository, BCryptPasswordEncoder bCryptPasswordEncoder, JWTUtil jwtUtil){
        this.repository = repository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public User doLogin(LoginDto dto) throws AuthenticationException, IOException {
        User entity = repository.findByEmail(dto.getEmail());

        if(entity == null){
            throw new AuthenticationException("User not Found");
        }

        if(!bCryptPasswordEncoder.matches(dto.getPassword(), entity.getPassword())){
            throw new AuthenticationException("Invalid Password");
        }

        return entity;
    }

    public User getProfile(String userId) throws IOException {
        return repository.findByEmail(userId);
    }

    public void deleteUser(String userId) {
        repository.deleteByEmail(userId);
    }

    public boolean checkId(String userId){
        return repository.existsByEmail(userId);
    }

    public void modifyProfile(String userId, ProfileDto dto) {

    }
}
