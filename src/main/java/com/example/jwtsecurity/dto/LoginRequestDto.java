package com.example.jwtsecurity.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
    private String username;
    private String password;
}
