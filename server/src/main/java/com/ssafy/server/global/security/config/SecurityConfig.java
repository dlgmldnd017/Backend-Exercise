package com.ssafy.server.global.security.config;


import com.ssafy.server.global.redis.repository.RefreshTokenRepository;
import com.ssafy.server.global.filter.JWTFilter;
import com.ssafy.server.global.filter.LoginFilter;
import com.ssafy.server.global.redis.service.RedisService;
import com.ssafy.server.global.security.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisService redisService;

    /*
    * 인증 매니저
    *
    * @Bean 등록을 명시적으로 선언하고 관련된 인증 매니저 객체를 반환
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /*
    * 암호화
    *
    * 비밀번호 저장시 보안 강화를 위해 암호화 수행
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    * 필터 체인
    *
    * SecurityFilterChain는 Spring Security에서 보안 필터 체인을 구성하는 데 사용되는 인터페이스
    * 그러므로, 이 필터 체인은 HTTP 요청에 대한 보안 규칙과 처리하기 위한 필터를 정의
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // RESTful API목적이고 STATELESS한 특성이기 때문에 csrf에 대한 보호가 필요없음
        http
                .csrf((auth) -> auth.disable());

        // JSON WEB TOKEN을 사용하므로, 필요없음
        http
                .formLogin((auth) -> auth.disable());

        // HTTP 기본 인증은 사용자 이름과 암호를 평문으로 전송하기 때문에 disable 설정
        http
                .httpBasic((auth) -> auth.disable());

        // .permitAll()로 선언된 경로는 모두 허가
        // 그 외 경로는 인증 필요
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .requestMatchers("/auth/**", "/join", "/socket/**", "/sub/**").permitAll()
                        .anyRequest().authenticated());

        // 로그인 필터 전에 JWTFilter를 거치게 함으로써 어떤 경로로 들어왔는지 또는 헤더에 담고 있는 것이 유효한지 체크
        http
                .addFilterBefore(new JWTFilter(jwtUtil, redisService, refreshTokenRepository), LoginFilter.class);

        // 로그인 필터와 UsernamePasswordAuthenticationFilter 클래스를 등록함으로써 로그인 처리
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshTokenRepository, redisService),
                        UsernamePasswordAuthenticationFilter.class);

        // 세션을 사용하지 않고 바로 인증만 거치기 때문에 STATELESS 선언
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}