package com.ssafy.server.global.security.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class RefreshTokenDTO {
    private Long userSeq;
    private String refreshToken;

    @Builder
    public RefreshTokenDTO(Long userSeq, String refreshToken) {
        this.userSeq = userSeq;
        this.refreshToken = refreshToken;
    }
}