package com.aiinterview.interviewai.dto;

import com.aiinterview.interviewai.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProfileResponseDto {

    private Long id;
    private String fullName;
    private String userName;
    private String email;
    private String phoneNumber;
    private Role role;
    private String profileImageUrl;
}
