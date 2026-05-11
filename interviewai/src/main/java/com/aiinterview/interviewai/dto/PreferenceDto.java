package com.aiinterview.interviewai.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PreferenceDto {

    private String defaultInterviewType;
    private String avatarStyle;
    private String language;
}
