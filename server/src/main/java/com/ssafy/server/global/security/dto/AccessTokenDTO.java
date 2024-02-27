package com.ssafy.server.global.security.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AccessTokenDTO {
    private Long userSeq;
    private String nickname;
    private String accessToken;

    @Builder
    public AccessTokenDTO(Long userSeq, String nickname, String accessToken) {
        this.userSeq = userSeq;
        this.nickname = nickname;
        this.accessToken = accessToken;
    }
}