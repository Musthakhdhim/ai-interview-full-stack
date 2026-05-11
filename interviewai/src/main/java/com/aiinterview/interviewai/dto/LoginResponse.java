package com.aiinterview.interviewai.dto;

import com.aiinterview.interviewai.entity.Role;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {

    private Long id;
    private String userName;
    private String email;
    private Role role;
    private String jwt;

}
