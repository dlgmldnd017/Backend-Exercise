package com.ssafy.server.domain.user.controller;

import com.ssafy.server.domain.user.dto.ProfileDto;
import com.ssafy.server.domain.user.entity.User;
import com.ssafy.server.domain.user.service.UserService;
import com.ssafy.server.global.jwt.util.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    private UserService userService;
    private JWTUtil jwtUtil;

    public UserController(UserService userService, JWTUtil jwtUtil) {
        super();
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/info/{userId}")
    public ResponseEntity<Map<String, Object>> getInfo(@PathVariable("userId") String userId,
                                                       HttpServletRequest request) {
        System.out.println("UserController.getInfo");

        Map<String, Object> resultMap = new HashMap<>();
        HttpStatus status = HttpStatus.ACCEPTED;

        try {
            User user = userService.findByEmail(userId);
            ProfileDto dto = ProfileDto.builder()
                    .email(user.getEmail())
                    .name(user.getName())
                    .gender(user.getGender())
                    .birthDate(user.getBirthDate())
                    .build();
            resultMap.put("userInfo", dto);
            status = HttpStatus.OK;
        } catch (Exception e) {
            resultMap.put("message", e.getMessage());
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return new ResponseEntity<Map<String, Object>>(resultMap, status);
    }
}