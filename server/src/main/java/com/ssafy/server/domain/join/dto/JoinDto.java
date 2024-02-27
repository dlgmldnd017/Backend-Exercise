package com.ssafy.server.domain.join.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class JoinDto {
  private String email;
  private String password;
  private String name;
  private String gender;
  private String birthDate;
}