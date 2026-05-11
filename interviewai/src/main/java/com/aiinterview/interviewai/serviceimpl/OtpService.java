package com.aiinterview.interviewai.serviceimpl;

import com.aiinterview.interviewai.dto.OtpData;
import com.aiinterview.interviewai.entity.OtpType;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class OtpService {

    // Cache for storing OTP data (expires automatically)
    private final Cache<String, OtpData> otpCache;

    // Track OTP verification status (separate from OTP data)
    private final Map<String, Boolean> verifiedOtps;

    // Rate limiting: track OTP request counts
    private final Map<String, Integer> otpRequestCounts;

    // Rate limiting: track blocked users
    private final Map<String, Long> otpRequestBlockedUntil;

    // Track failed OTP attempts
    private final Map<String, Integer> failedAttempts;

    // Scheduled executor for cleanup tasks
    private final ScheduledExecutorService scheduler;

    // Secure random generator for OTP
    private final SecureRandom secureRandom;

    // Configuration constants
    private static final int OTP_LENGTH = 6;
    private static final int OTP_EXPIRY_SECONDS = 180; // 3 minutes
    private static final int MAX_OTP_REQUESTS_PER_HOUR = 3;
    private static final int BLOCK_DURATION_MINUTES = 15;
    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int FAILED_ATTEMPTS_WINDOW_MINUTES = 5;
    private static final int CLEANUP_INTERVAL_SECONDS = 30;
    private static final int MAX_CACHE_SIZE = 10000;

    public OtpService() {
        // Initialize Caffeine cache with automatic expiry
        this.otpCache = Caffeine.newBuilder()
                .expireAfterWrite(OTP_EXPIRY_SECONDS, TimeUnit.SECONDS)
                .maximumSize(MAX_CACHE_SIZE)
                .recordStats()
                .build();

        // Initialize tracking maps
        this.verifiedOtps = new ConcurrentHashMap<>();
        this.otpRequestCounts = new ConcurrentHashMap<>();
        this.otpRequestBlockedUntil = new ConcurrentHashMap<>();
        this.failedAttempts = new ConcurrentHashMap<>();

        // Initialize scheduler for cleanup
        this.scheduler = Executors.newSingleThreadScheduledExecutor();

        // Initialize secure random generator
        this.secureRandom = new SecureRandom();

        log.info("OtpService initialized with expiry: {} seconds, max requests: {}/hour",
                OTP_EXPIRY_SECONDS, MAX_OTP_REQUESTS_PER_HOUR);
    }

    @PostConstruct
    public void startCleanup() {
        // Run cleanup every 30 seconds to remove expired entries
        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries,
                CLEANUP_INTERVAL_SECONDS,
                CLEANUP_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
        log.info("OTP cleanup scheduler started");
    }

    /**
     * Generate a new OTP for a user
     */
    public String generateOtp(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);

        // Check rate limiting
        if (!canRequestOtp(userEmail, type)) {
            Long blockedUntil = otpRequestBlockedUntil.get(identifier);
            long remainingSeconds = (blockedUntil - System.currentTimeMillis()) / 1000;
            throw new RuntimeException("Too many OTP requests. Please try again after " +
                    remainingSeconds + " seconds.");
        }

        // Generate 6-digit OTP
        String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

        // Create OTP data with timestamp
        OtpData otpData = OtpData.builder()
                .otp(otp)
                .generatedAt(System.currentTimeMillis())
                .expirySeconds(OTP_EXPIRY_SECONDS)
                .type(type)
                .attempts(0)
                .build();

        // Store in cache
        otpCache.put(identifier, otpData);

        // Increment request count for rate limiting
        incrementOtpRequestCount(userEmail, type);

        // Clear any previous verification status
        clearVerifiedOtp(userEmail, type);
        clearFailedAttempts(userEmail, type);

        // Log OTP for debugging (remove in production)
        log.info("OTP generated for {} ({}): {}", userEmail, type, otp);

        return otp;
    }

    /**
     * Validate OTP for a user
     */
    public boolean validateOtp(String userEmail, OtpType type, String otp) {
        String identifier = buildIdentifier(userEmail, type);

        // Check if user is blocked due to too many failed attempts
        if (isUserBlocked(userEmail, type)) {
            log.warn("User {} is blocked for {} OTP validation", userEmail, type);
            return false;
        }

        // Get OTP data from cache
        OtpData otpData = otpCache.getIfPresent(identifier);

        // Check if OTP exists
        if (otpData == null) {
            recordFailedAttempt(userEmail, type);
            log.warn("OTP validation failed for {} ({}): OTP not found", userEmail, type);
            return false;
        }

        // Check if OTP is expired (manual check as additional safety)
        long elapsed = System.currentTimeMillis() - otpData.getGeneratedAt();
        if (elapsed > otpData.getExpirySeconds() * 1000L) {
            otpCache.invalidate(identifier);
            recordFailedAttempt(userEmail, type);
            log.warn("OTP validation failed for {} ({}): OTP expired", userEmail, type);
            return false;
        }

        // Check if OTP matches
        if (!otpData.getOtp().equals(otp)) {
            recordFailedAttempt(userEmail, type);
            log.warn("OTP validation failed for {} ({}): Invalid OTP", userEmail, type);
            return false;
        }

        // OTP is valid - cleanup
        otpCache.invalidate(identifier);
        clearFailedAttempts(userEmail, type);

        log.info("OTP validated successfully for {} ({})", userEmail, type);
        return true;
    }

    /**
     * Mark that OTP has been verified for a user
     */
    public void markOtpVerified(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        verifiedOtps.put(identifier, true);
        log.info("OTP marked as verified for {} ({})", userEmail, type);
    }

    /**
     * Check if OTP has been verified for a user
     */
    public boolean isOtpVerified(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        return verifiedOtps.getOrDefault(identifier, false);
    }

    /**
     * Clear OTP verification status
     */
    public void clearVerifiedOtp(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        verifiedOtps.remove(identifier);
        log.debug("Verified OTP cleared for {} ({})", userEmail, type);
    }

    /**
     * Check if user can request a new OTP (rate limiting)
     */
    public boolean canRequestOtp(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);

        // Check if user is blocked
        Long blockedUntil = otpRequestBlockedUntil.get(identifier);
        if (blockedUntil != null && System.currentTimeMillis() < blockedUntil) {
            long remainingSeconds = (blockedUntil - System.currentTimeMillis()) / 1000;
            log.debug("OTP request blocked for {} ({}): {} seconds remaining",
                    userEmail, type, remainingSeconds);
            return false;
        }

        // Remove expired block
        if (blockedUntil != null && System.currentTimeMillis() >= blockedUntil) {
            otpRequestBlockedUntil.remove(identifier);
            otpRequestCounts.remove(identifier);
        }

        // Check request count
        Integer count = otpRequestCounts.getOrDefault(identifier, 0);
        if (count >= MAX_OTP_REQUESTS_PER_HOUR) {
            // Block user for BLOCK_DURATION_MINUTES
            long blockUntil = System.currentTimeMillis() + (BLOCK_DURATION_MINUTES * 60 * 1000);
            otpRequestBlockedUntil.put(identifier, blockUntil);
            log.warn("OTP request limit exceeded for {} ({}). Blocked until {}",
                    userEmail, type, LocalDateTime.now().plusMinutes(BLOCK_DURATION_MINUTES));
            return false;
        }

        return true;
    }

    /**
     * Get remaining block time in seconds for a blocked user (NEW METHOD)
     */
    public long getRemainingBlockTime(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        Long blockedUntil = otpRequestBlockedUntil.get(identifier);

        if (blockedUntil == null || System.currentTimeMillis() >= blockedUntil) {
            return 0;
        }

        return (blockedUntil - System.currentTimeMillis()) / 1000;
    }

    /**
     * Increment OTP request count for rate limiting
     */
    public void incrementOtpRequestCount(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        otpRequestCounts.merge(identifier, 1, Integer::sum);

        // Reset counter after 1 hour
        scheduler.schedule(() -> {
            otpRequestCounts.remove(identifier);
            otpRequestBlockedUntil.remove(identifier);
            log.debug("OTP request count reset for {} ({})", userEmail, type);
        }, 1, TimeUnit.HOURS);
    }

    /**
     * Check if OTP exists and is valid (without consuming it)
     */
    public boolean isOtpValid(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        OtpData otpData = otpCache.getIfPresent(identifier);

        if (otpData == null) {
            return false;
        }

        long elapsed = System.currentTimeMillis() - otpData.getGeneratedAt();
        return elapsed <= otpData.getExpirySeconds() * 1000L;
    }

    /**
     * Get remaining validity seconds for OTP
     */
    public long getOtpRemainingSeconds(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        OtpData otpData = otpCache.getIfPresent(identifier);

        if (otpData == null) {
            return 0;
        }

        long elapsed = System.currentTimeMillis() - otpData.getGeneratedAt();
        long remaining = otpData.getExpirySeconds() - (elapsed / 1000);
        return Math.max(0, remaining);
    }

    /**
     * Manually invalidate OTP for a user
     */
    public void invalidateOtp(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        otpCache.invalidate(identifier);
        clearVerifiedOtp(userEmail, type);
        clearFailedAttempts(userEmail, type);
        log.info("OTP invalidated for {} ({})", userEmail, type);
    }

    /**
     * Record failed OTP attempt for fraud detection
     */
    private void recordFailedAttempt(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        int attempts = failedAttempts.getOrDefault(identifier, 0) + 1;
        failedAttempts.put(identifier, attempts);

        // Schedule reset of failed attempts after window
        scheduler.schedule(() -> {
            clearFailedAttempts(userEmail, type);
        }, FAILED_ATTEMPTS_WINDOW_MINUTES, TimeUnit.MINUTES);

        log.warn("Failed OTP attempt {} for {} ({})", attempts, userEmail, type);
    }

    /**
     * Clear failed attempts for a user
     */
    private void clearFailedAttempts(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        failedAttempts.remove(identifier);
    }

    /**
     * Check if user is blocked due to too many failed attempts
     */
    private boolean isUserBlocked(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        Integer attempts = failedAttempts.get(identifier);
        return attempts != null && attempts >= MAX_FAILED_ATTEMPTS;
    }

    /**
     * Get number of remaining failed attempts before block
     */
    public int getRemainingFailedAttempts(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        Integer attempts = failedAttempts.get(identifier);
        if (attempts == null) {
            return MAX_FAILED_ATTEMPTS;
        }
        return Math.max(0, MAX_FAILED_ATTEMPTS - attempts);
    }

    /**
     * Clean up expired entries from all maps
     */
    private void cleanupExpiredEntries() {
        long now = System.currentTimeMillis();
        int cleaned = 0;

        // Clean up expired blocks
        for (Map.Entry<String, Long> entry : otpRequestBlockedUntil.entrySet()) {
            if (now >= entry.getValue()) {
                otpRequestBlockedUntil.remove(entry.getKey());
                otpRequestCounts.remove(entry.getKey());
                cleaned++;
            }
        }

        // Clean up expired verification statuses (optional - they don't expire automatically)
        // You could add TTL for verifiedOtps if needed

        if (cleaned > 0) {
            log.debug("Cleaned up {} expired entries from rate limiting maps", cleaned);
        }
    }

    /**
     * Build unique identifier for a user and OTP type
     */
    private String buildIdentifier(String userEmail, OtpType type) {
        return String.format("%s:%s", userEmail.toLowerCase().trim(), type.name());
    }

    /**
     * Get cache statistics for monitoring
     */
    public String getCacheStats() {
        return String.format("Cache size: %d, Hit rate: %.2f%%, Miss rate: %.2f%%, Evictions: %d",
                otpCache.estimatedSize(),
                otpCache.stats().hitRate() * 100,
                otpCache.stats().missRate() * 100,
                otpCache.stats().evictionCount());
    }

    /**
     * Get current request count for a user (for monitoring)
     */
    public int getRequestCount(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        return otpRequestCounts.getOrDefault(identifier, 0);
    }

    /**
     * Check if user is currently blocked from requesting OTP
     */
    public boolean isUserBlockedFromRequesting(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        Long blockedUntil = otpRequestBlockedUntil.get(identifier);
        return blockedUntil != null && System.currentTimeMillis() < blockedUntil;
    }

    /**
     * Get block expiry time for a blocked user
     */
    public Long getBlockExpiryTime(String userEmail, OtpType type) {
        String identifier = buildIdentifier(userEmail, type);
        return otpRequestBlockedUntil.get(identifier);
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down OtpService...");
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Clear all maps
        otpCache.invalidateAll();
        verifiedOtps.clear();
        otpRequestCounts.clear();
        otpRequestBlockedUntil.clear();
        failedAttempts.clear();

        log.info("OtpService shutdown complete");
    }
}