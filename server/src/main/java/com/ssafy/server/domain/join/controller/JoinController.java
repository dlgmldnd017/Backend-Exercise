package com.ssafy.server.domain.join.controller;


import com.ssafy.server.domain.join.dto.JoinDto;
import com.ssafy.server.domain.join.service.JoinService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/join")
public class JoinController {

  private final JoinService joinService;

  public JoinController(JoinService joinService) {
    this.joinService = joinService;
  }

  @PostMapping
  public String joinProcess(JoinDto joinDto) {
    joinService.joinProcess(joinDto);
    return "ok";
  }
}