package com.ssafy.server.global.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssafy.server.domain.login.dto.LoginDto;
import com.ssafy.server.domain.user.detail.CustomUserDetails;
import com.ssafy.server.global.redis.repository.RefreshTokenRepository;
import com.ssafy.server.global.redis.service.RedisService;
import com.ssafy.server.global.response.Response;
import com.ssafy.server.global.security.dto.TokenDTO;
import com.ssafy.server.global.security.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private ObjectMapper mapper = new ObjectMapper();

    private final AuthenticationManager authenticationManager;
    //JWTUtil 주입
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisService redisService;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshTokenRepository refreshTokenRepository, RedisService redisService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
        this.redisService = redisService;
        this.setFilterProcessesUrl("/auth/login");
    }

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter("email");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse Response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authToken;

        // json형태로 request 받는다면
        if (request.getContentType().equals("application/json")) {
            try {
                // 클라이언트의 요청이 DispatcherServlet에 도달하기 전에 가로챔.
                // 가로챈 request에서 json을 추출 후 objectMapper를 이용해 loginDto 객체로 변환
                LoginDto dto = mapper.readValue(
                        request.getReader().lines().collect(Collectors.joining()), LoginDto.class);

                // Spring Security에서 AuthenticationManager에게 인증을 받으려면 Dto처럼 userId와 password를 Token에 담아서 보내줘야함.
                authToken = new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword(), null); // 3번째 인자로 role 값을 넣는다.
            } catch (IOException e) {
                e.printStackTrace();
                throw new AuthenticationServiceException("Request Content-Type(application/json)");
            }
        }
        // json형태가 아닌 form 요청이라면
        else {
            // 클라이언트의 요청이 DispatcherServlet에 도달하기 전에 가로채서 userId와 password를 추출.
            String email = obtainUsername(request);
            String password = obtainPassword(request);
            authToken = new UsernamePasswordAuthenticationToken(email, password, null); // 3번째 인자로 role 값을 넣는다.
        }

        // Token을 검증하기 위해 AuthenticationManager에게 전달.
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        System.out.println("LoginFilter.successfulAuthentication");

        // 사용자의 이메일과 PK(ID)를 저장
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String email = userDetails.getUser().getEmail();

        // Access와 Refresh 토큰을 생성
        TokenDTO tokenDTO = jwtUtil.generateToken(email);

        // redis에 refresh 토큰 저장
        redisService.saveToken(email, tokenDTO.getRefreshToken());

        // 응답 메시지 설정 (msg)
        setTokenResponse(response, tokenDTO.getAccessToken(), tokenDTO.getRefreshToken());
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse
            response, AuthenticationException failed) throws IOException {
        System.out.println("LoginFilter.unsuccessfulAuthentication");

        // 403 응답 코드 반환
        Map<String, String> result = new TreeMap<>();
        result.put("msg", "아이디 또는 비밀번호가 일치하지 않습니다.");

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(
                mapper.writeValueAsString(
                        Response.fail(result)));
        response.setStatus(403);
    }

    private void setTokenResponse(HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        // JSON으로 token 전달
        Map<String, Object> result = new TreeMap<>();
        result.put("access-token", accessToken);
        result.put("refresh-token", refreshToken);

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(
                mapper.writeValueAsString(
                        Response.success(result)));
    }
}