package com.example.jwtsecurity.config;

import com.example.jwtsecurity.filter.MyFilter1;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    /**
     내가 필터를 직접 만드는 방법
     1. filter폴더에 생성
     2. filterConfig에 filter를 추가 시킨다
     굳이 시큐리티에 필터체인을 걸 필요가 없다
     * */

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){

        FilterRegistrationBean<MyFilter1>bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); //낮은 번호가 필터중에서 가장 먼저 실행

        return bean;
    }


}
