<?php
/**
 * Rate Limiter for Form Protection
 * 
 * Provides rate limiting functionality to prevent form spam
 * Used with the formProtectionHook to limit the number of submissions.
 * 
 * @package formprotection
 */

/**
 * Check if a request is rate limited based on IP, User-Agent, and a cookie
 * 
 * @param string $actionKey A unique identifier for the action being rate limited
 * @param int $limitSeconds The number of seconds to enforce rate limiting
 * @param string $cookieName The name of the cookie used for rate limiting (default: 'submission')
 * @return bool True if rate limited, false otherwise
 */
function isRateLimited($actionKey, $limitSeconds = 10, $cookieName = 'submission') {
    // Get client IP address and User-Agent
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // Generate a unique cookie if it doesn't exist
    if (!isset($_COOKIE[$cookieName])) {
        $cookieValue = bin2hex(random_bytes(16)); // Generate a random token
        setcookie($cookieName, $cookieValue, time() + (86400 * 30), "/"); // 30-day expiration
    } else {
        $cookieValue = $_COOKIE[$cookieName];
    }

    // Create a unique key based on the action, IP, User-Agent, and cookie
    $key = md5($actionKey . '_' . $ip . '_' . $userAgent . '_' . $cookieValue);

    // Set the file path in the temp directory
    $file = sys_get_temp_dir() . "/ratelimit_{$key}.tmp";

    // Get current timestamp
    $now = time();

    // Check if a record exists for this key
    if (file_exists($file)) {
        $last = (int)file_get_contents($file);

        // If the time elapsed is less than the limit, rate limit
        if (($now - $last) < $limitSeconds) {
            return true;
        }
    }

    // Store the current timestamp
    file_put_contents($file, $now);

    // Not rate limited
    return false;
}