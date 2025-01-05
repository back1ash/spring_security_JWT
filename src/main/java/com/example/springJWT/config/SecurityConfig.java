package com.example.springJWT.config;

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

import com.example.springJWT.jwt.LoginFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean

  @Configuration
  @EnableWebSecurity
  public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

      return new BCryptPasswordEncoder();
    }

    private final AuthenticationConfiguration authenticationConfiguration;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration) {

      this.authenticationConfiguration = authenticationConfiguration;
    }

    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

      return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

      http
          .csrf((auth) -> auth.disable());

      http
          .formLogin((auth) -> auth.disable());

      http
          .httpBasic((auth) -> auth.disable());

      http
          .authorizeHttpRequests((auth) -> auth
              .requestMatchers("/login", "/", "/join").permitAll()
              .anyRequest().authenticated());

      // 필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에
      // authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
      http
          .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)),
              UsernamePasswordAuthenticationFilter.class);

      http
          .sessionManagement((session) -> session
              .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

      return http.build();
    }
  }
}