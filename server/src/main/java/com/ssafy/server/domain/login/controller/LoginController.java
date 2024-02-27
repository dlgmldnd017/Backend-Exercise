package com.ssafy.server.domain.login.controller;


import com.ssafy.server.domain.login.dto.LoginDto;
import com.ssafy.server.domain.login.service.LoginService;
import com.ssafy.server.domain.user.detail.CustomUserDetails;
import com.ssafy.server.domain.user.dto.ProfileDto;
import com.ssafy.server.domain.user.entity.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class LoginController {

    private final LoginService service;

    public LoginController(LoginService service) {
        this.service = service;
    }

    @PostMapping("/login")
    public ResponseEntity<?> doLogin(@RequestBody LoginDto dto) {
        System.out.println("LoginController.doLogin");
        Map<String, String> result = new HashMap<>();

        try {
            User entity = service.doLogin(dto);

            if (entity != null) {
//        result.put("access-token", accessToken);
//        result.put("refresh-token", refreshToken);
                return new ResponseEntity<>(result, HttpStatus.OK);
            } else return new ResponseEntity<>(result, HttpStatus.BAD_REQUEST);

        } catch (Exception e) {
            e.printStackTrace();
            result.put("message", "Login is failed");
            return new ResponseEntity<>(result, HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/me")
    public ResponseEntity<ProfileDto> getProfile(Authentication authentication) throws IOException {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        User entity = service.getProfile(userDetails.getUsername());

        if (entity == null) {
            Map<String, String> result = new HashMap<>();
            result.put("message", "failed");
            return new ResponseEntity(result, HttpStatus.BAD_REQUEST);
        } else {
            ProfileDto dto = ProfileDto.builder()
                    .email(entity.getEmail())
                    .name(entity.getName())
                    .gender(entity.getGender())
                    .birthDate(entity.getBirthDate())
                    .build();

            return new ResponseEntity<>(dto, HttpStatus.OK);
        }
    }

    @GetMapping("/{userId}")
    public ResponseEntity checkId(@PathVariable("userId") String userId) {
        Boolean isExist = service.checkId(userId);

        Map<String, String> result = new HashMap<>();

        if (isExist) {
            result.put("message", "이미 존재하는 사용자 ID입니다.");
            return new ResponseEntity(result, HttpStatus.OK);
        } else {
            result.put("message", "사용 가능한 ID 입니다.");
            return new ResponseEntity(result, HttpStatus.OK);
        }
    }

    @PatchMapping("/{userId}")
    public ResponseEntity modifyProfile(@PathVariable("userId") String userId,
                                        @RequestBody ProfileDto profileDto) {
        service.modifyProfile(userId, profileDto);

        Map<String, String> result = new HashMap<>();
        result.put("message", "success");
        return new ResponseEntity(result, HttpStatus.OK);
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable("userId") String userId,
                                        Authentication authentication) {

        Map<String, String> result = new HashMap<>();
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        if (userDetails.getUsername().equals(userId)) {
            service.deleteUser(userId);
            result.put("message", "success");
            return new ResponseEntity<>(result, HttpStatus.OK);
        } else {
            result.put("message", "failed");
            return new ResponseEntity<>(result, HttpStatus.BAD_REQUEST);
        }
    }
}