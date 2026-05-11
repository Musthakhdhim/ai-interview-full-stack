package com.aiinterview.interviewai.dto;

import com.aiinterview.interviewai.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegisterResponse {

    private Long id;
    private String userName;
    private String email;
    private Role role;
    private boolean requireVerification;
}
