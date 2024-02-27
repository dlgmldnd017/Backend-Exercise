package com.ssafy.server.domain.join.service;


import com.ssafy.server.domain.join.dto.JoinDto;
import com.ssafy.server.domain.user.entity.User;
import com.ssafy.server.domain.user.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.userRepository = userRepository;
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  public void joinProcess(JoinDto dto) {
    Boolean isExist = userRepository.existsByEmail(dto.getEmail());

    if (isExist) return;

    User data = new User();
    data.setEmail(dto.getEmail());
    data.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
    data.setName(dto.getName());
    data.setGender(dto.getGender());
    data.setBirthDate(dto.getBirthDate());

    userRepository.save(data);
  }
}
