package com.ssafy.server.domain.user.service;

import com.ssafy.server.domain.user.entity.User;
import com.ssafy.server.domain.user.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class UserService {
    private final UserRepository repository;

    public UserService(UserRepository repository){
        this.repository = repository;
    }

    public User findByEmail(String email) throws IOException {
        return repository.findByEmail(email);
    }

    public User getLoginUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
