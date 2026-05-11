package com.aiinterview.interviewai.dto;

import com.aiinterview.interviewai.entity.OtpType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class OtpData {
    private String otp;
    private long generatedAt;
    private int expirySeconds;
    private OtpType type;
    private int attempts;

    public boolean isExpired() {
        return System.currentTimeMillis() > generatedAt + (expirySeconds * 1000L);
    }

    // Helper method to get remaining seconds
    public long getRemainingSeconds() {
        long remaining = (generatedAt + (expirySeconds * 1000L)) - System.currentTimeMillis();
        return remaining > 0 ? remaining / 1000 : 0;
    }
}
