package com.example.jwtsecurity.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration(); //내 서버가 응답할때 json을 js에서 처리할수 있게 할지를 설정 하는 것
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");   //모든 ip에 응답을 허용
        config.addAllowedHeader("*");   //모든 header 에 응답을 허용
        config.addAllowedMethod("*");   //모든 메서드 요청을 허용
        source.registerCorsConfiguration("/api/**", config);  //해당 주소는 "" 위의 config 설정을 따라라
        return new CorsFilter(source);

    }

}
