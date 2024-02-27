package com.ssafy.server.domain.user.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ProfileDto {
    private String email;
    private String name;
    private String gender;
    private String birthDate;
}