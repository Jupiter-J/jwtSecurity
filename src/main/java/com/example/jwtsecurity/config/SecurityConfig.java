package com.example.jwtsecurity.config;

import com.example.jwtsecurity.config.jwt.JwtAuthenticationFilter;
import com.example.jwtsecurity.filter.MyFilter1;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.Filter;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Bean
    public BCryptPasswordEncoder encode() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class);

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠다
            .and()
                .addFilter(corsFilter)  //모든 요청은 필터를 거친다(인증이 필요할때 사용), @CorsOrigin 은 인증이 필요없을때 사용
                .formLogin().disable()  //폼로그인 안쓰겠다
                .httpBasic().disable()  //기본 인증방식 사용 X
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) //필터 추가 , AuthenticationManager 파라미터 필요
                .authorizeRequests()
                .antMatchers("/api/vi/user/**")
                    .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN') ")
                .antMatchers("/api/v1/manager/**")
                    .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                    .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()


        ;
    }
}
