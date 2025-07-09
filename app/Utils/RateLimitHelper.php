<?php

namespace App\Utils;

use App\Exceptions\ApiException;
use Illuminate\Support\Facades\Redis;

class RateLimitHelper
{
    /**
     * Apply rate limiting for specific endpoints
     *
     * @param \Illuminate\Http\Request $request
     * @param \App\Models\User $user
     * @param string $ip
     * @return void
     * @throws ApiException
     */
    public static function applyEndpointRateLimiting($request, $user, $ip)
    {
        if ($request->is('api/v1/client/subscribe')) {
            self::applySubscribeRateLimiting($user, $ip);
        }
    }

    /**
     * Apply rate limiting for subscribe endpoint
     *
     * @param \App\Models\User $user
     * @param string $ip
     * @return void
     * @throws ApiException
     */
    public static function applySubscribeRateLimiting($user, $ip)
    {
        // User-based rate limiting
        self::checkUserRateLimit($user->id, 10, 1); // 10 requests per minute
        
        // IP-based rate limiting
        self::checkIpRateLimit($ip, 30, 1); // 30 requests per minute
    }

    /**
     * Check user-based rate limit
     *
     * @param int $userId
     * @param int $maxAttempts
     * @param int $decayMinutes
     * @return void
     * @throws ApiException
     */
    public static function checkUserRateLimit($userId, $maxAttempts, $decayMinutes)
    {
        $userKey = 'subscribe_limit:' . $userId;
        
        if (Redis::exists($userKey)) {
            $userAttempts = Redis::get($userKey);
            if ($userAttempts >= $maxAttempts) {
                throw new ApiException('Access Denied(1009)', 200);
            }
            Redis::incr($userKey);
        } else {
            Redis::setex($userKey, 60 * $decayMinutes, 1);
        }
    }

    /**
     * Check IP-based rate limit
     *
     * @param string $ip
     * @param int $maxAttempts
     * @param int $decayMinutes
     * @return void
     * @throws ApiException
     */
    public static function checkIpRateLimit($ip, $maxAttempts, $decayMinutes)
    {
        $ipKey = 'subscribe_ip_limit:' . $ip;
        
        if (Redis::exists($ipKey)) {
            $ipAttempts = Redis::get($ipKey);
            if ($ipAttempts >= $maxAttempts) {
                throw new ApiException('Access Denied(1010)', 200);
            }
            Redis::incr($ipKey);
        } else {
            Redis::setex($ipKey, 60 * $decayMinutes, 1);
        }
    }

    /**
     * Check and update IP user access tracking
     *
     * @param string $ip
     * @param int $userId
     * @param string|null $token
     * @return void
     */
    public static function checkIpUserAccess($ip, $userId, $token = null)
    {
        try {
            // Check if IP is in whitelist first
            if (self::isIpWhitelisted($ip)) {
                self::logIpUserAccess($ip, $userId, 'whitelist_access', $token, [
                    'message' => 'IP is whitelisted, skipping access limits'
                ]);
                return; // Skip all access tracking and limits for whitelisted IPs
            }
            
            $trackingKey = 'ip_user_access:' . $ip;
            $maxDifferentUsers = 10;
            $trackingPeriod = 60 * 60 * 24; // 24 hours
            
            // Get or initialize tracking data
            $trackingData = self::getOrInitializeIpUserTracking($trackingKey, $trackingPeriod);
            
            // Process user access and update with Pipeline
            if (self::isNewUserForIp($trackingData, $userId)) {
                self::handleNewUserAccessWithPipeline($ip, $userId, $trackingData, $maxDifferentUsers, $trackingKey, $trackingPeriod, $token);
            } else {
                self::handleExistingUserAccessWithPipeline($ip, $userId, $trackingData, $trackingKey, $trackingPeriod, $token);
            }
            
        } catch (\Exception $e) {
            self::handleIpUserAccessError($e, $ip, $userId);
        }
    }

    /**
     * Check if IP is in whitelist
     *
     * @param string $ip
     * @return bool
     */
    public static function isIpWhitelisted($ip)
    {
        try {
            $whitelistKey = 'ip_whitelist:' . $ip;
            return Redis::exists($whitelistKey);
        } catch (\Exception $e) {
            \Log::error("Failed to check IP whitelist: " . $e->getMessage(), [
                'ip' => $ip,
                'exception' => $e->getTraceAsString()
            ]);
            return false; // If whitelist check fails, proceed with normal access checks
        }
    }

    /**
     * Get or initialize IP user tracking data
     *
     * @param string $trackingKey
     * @param int $trackingPeriod
     * @return array
     */
    public static function getOrInitializeIpUserTracking($trackingKey, $trackingPeriod)
    {
        try {
            $trackingDataJson = Redis::get($trackingKey);
            $trackingData = $trackingDataJson ? json_decode($trackingDataJson, true) : [];
        } catch (\Exception $e) {
            $trackingData = [];
        }
        
        $currentTime = time();
        
        // Initialize if empty or expired
        if (empty($trackingData) || self::isTrackingDataExpired($trackingData, $currentTime, $trackingPeriod)) {
            return [
                'user_ids' => [],
                'first_access' => $currentTime,
                'last_updated' => $currentTime
            ];
        }
        
        return $trackingData;
    }

    /**
     * Check if tracking data has expired
     *
     * @param array $trackingData
     * @param int $currentTime
     * @param int $trackingPeriod
     * @return bool
     */
    public static function isTrackingDataExpired($trackingData, $currentTime, $trackingPeriod)
    {
        return isset($trackingData['first_access']) && 
               ($currentTime - $trackingData['first_access']) > $trackingPeriod;
    }

    /**
     * Check if user is new for this IP
     *
     * @param array $trackingData
     * @param int $userId
     * @return bool
     */
    public static function isNewUserForIp($trackingData, $userId)
    {
        return !in_array($userId, $trackingData['user_ids']);
    }

    /**
     * Handle existing user access for IP with Pipeline optimization
     *
     * @param string $ip
     * @param int $userId
     * @param array &$trackingData
     * @param string $trackingKey
     * @param int $trackingPeriod
     * @param string|null $token
     * @return void
     */
    public static function handleExistingUserAccessWithPipeline($ip, $userId, &$trackingData, $trackingKey, $trackingPeriod, $token = null)
    {
        $trackingData['last_updated'] = time();
        
        // Create log data
        $logData = self::createIpUserAccessLogData($ip, $userId, 'existing_user_access', $token, [
            'total_users_accessed' => count($trackingData['user_ids'])
        ]);
        
        // Use Pipeline to update tracking data and log simultaneously
        Redis::pipeline(function ($pipe) use ($trackingKey, $trackingPeriod, $trackingData, $logData) {
            // Update tracking data
            $pipe->setex($trackingKey, $trackingPeriod, json_encode($trackingData));
            
            // Add access log
            self::addIpUserAccessLogToPipeline($pipe, $logData);
        });
    }

    /**
     * Handle new user access for IP with Pipeline optimization
     *
     * @param string $ip
     * @param int $userId
     * @param array &$trackingData
     * @param int $maxDifferentUsers
     * @param string $trackingKey
     * @param int $trackingPeriod
     * @param string|null $token
     * @return void
     * @throws ApiException
     */
    public static function handleNewUserAccessWithPipeline($ip, $userId, &$trackingData, $maxDifferentUsers, $trackingKey, $trackingPeriod, $token = null)
    {
        // Add new user to tracking
        $trackingData['user_ids'][] = $userId;
        $trackingData['last_updated'] = time();
        
        // Check if limit exceeded
        if (count($trackingData['user_ids']) >= $maxDifferentUsers) {
            self::blacklistIpForTooManyUsers($ip, $userId, $trackingData, $maxDifferentUsers, $trackingKey, $token);
            throw new ApiException('Access Denied(1013)', 200);
        }
        
        // Create log data
        $logData = self::createIpUserAccessLogData($ip, $userId, 'new_user_access', $token, [
            'total_users_accessed' => count($trackingData['user_ids']),
            'max_allowed' => $maxDifferentUsers
        ]);
        
        // Use Pipeline to update tracking data and log simultaneously
        Redis::pipeline(function ($pipe) use ($trackingKey, $trackingPeriod, $trackingData, $logData) {
            // Update tracking data
            $pipe->setex($trackingKey, $trackingPeriod, json_encode($trackingData));
            
            // Add access log
            self::addIpUserAccessLogToPipeline($pipe, $logData);
        });
    }

    /**
     * Blacklist IP for accessing too many different users
     *
     * @param string $ip
     * @param int $userId
     * @param array $trackingData
     * @param int $maxDifferentUsers
     * @param string $trackingKey
     * @param string|null $token
     * @return void
     */
    public static function blacklistIpForTooManyUsers($ip, $userId, $trackingData, $maxDifferentUsers, $trackingKey, $token = null)
    {
        // Double-check: Never blacklist whitelisted IPs
        if (self::isIpWhitelisted($ip)) {
            // Create log data for whitelist protection event
            $logData = self::createIpUserAccessLogData($ip, $userId, 'blacklist_attempt_blocked_whitelist', $token, [
                'message' => 'Attempted to blacklist whitelisted IP, blocked',
                'user_ids_accessed' => $trackingData['user_ids'],
                'access_count' => count($trackingData['user_ids']),
                'max_allowed' => $maxDifferentUsers
            ]);
            
            // Use Pipeline for consistent logging
            Redis::pipeline(function ($pipe) use ($logData) {
                self::addIpUserAccessLogToPipeline($pipe, $logData);
            });
            
            return; // Skip blacklisting for whitelisted IPs
        }
        
        $blacklistKey = 'ip_blacklist:' . $ip;
        $blacklistInfo = [
            'reason' => 'too_many_user_accounts',
            'user_ids_accessed' => $trackingData['user_ids'],
            'access_count' => count($trackingData['user_ids']),
            'tracking_period_start' => date('Y-m-d H:i:s', $trackingData['first_access']),
            'blocked_at' => now()->toDateTimeString(),
            'user_agent' => request()->header('User-Agent'),
            'referer' => request()->header('Referer'),
            'all_headers' => request()->headers->all(),
        ];
        
        // Create log data for blacklist event
        $logData = self::createIpUserAccessLogData($ip, $userId, 'blacklisted', $token, [
            'user_ids_accessed' => $trackingData['user_ids'],
            'access_count' => count($trackingData['user_ids']),
            'max_allowed' => $maxDifferentUsers
        ]);
        
        // Use Pipeline to combine blacklist, delete tracking, and log operations
        Redis::pipeline(function ($pipe) use ($blacklistKey, $blacklistInfo, $trackingKey, $logData) {
            // Set blacklist for 7 days
            $pipe->setex($blacklistKey, 60 * 60 * 24 * 7, json_encode($blacklistInfo));
            
            // Clear tracking data since IP is now blacklisted
            $pipe->del($trackingKey);
            
            // Add blacklist log
            self::addIpUserAccessLogToPipeline($pipe, $logData);
        });
    }

    /**
     * Handle IP user access tracking errors
     *
     * @param \Exception $e
     * @param string $ip
     * @param int $userId
     * @return void
     * @throws ApiException
     */
    public static function handleIpUserAccessError($e, $ip, $userId)
    {
        \Log::error("IP user access tracking failed: " . $e->getMessage(), [
            'ip' => $ip,
            'user_id' => $userId,
            'exception' => $e->getTraceAsString()
        ]);
        
        // Re-throw ApiException (blacklist exceptions should still block access)
        if ($e instanceof ApiException) {
            throw $e;
        }
    }

    /**
     * Create IP user access log data
     *
     * @param string $ip
     * @param int $userId
     * @param string $action
     * @param string|null $token
     * @param array $extra
     * @return array
     */
    public static function createIpUserAccessLogData($ip, $userId, $action, $token = null, $extra = [])
    {
        return [
            'token' => $token,
            'ip' => $ip,
            'user_id' => $userId,
            'action' => $action,
            'timestamp' => time(),
            'datetime' => date('Y-m-d H:i:s'),
            'extra' => $extra,
        ];
    }

    /**
     * Add IP user access log to pipeline
     *
     * @param object $pipe
     * @param array $logData
     * @return void
     */
    public static function addIpUserAccessLogToPipeline($pipe, $logData)
    {
        $logKey = "ip_user_access_log";
        $pipe->lpush($logKey, json_encode($logData));
        $pipe->ltrim($logKey, 0, 1999);
        $pipe->expire($logKey, 7 * 24 * 60 * 60);
    }

    /**
     * Log IP user access events
     *
     * @param string $ip
     * @param int $userId
     * @param string $action
     * @param string|null $token
     * @param array $extra
     * @return void
     */
    public static function logIpUserAccess($ip, $userId, $action, $token = null, $extra = [])
    {
        try {
            $logData = self::createIpUserAccessLogData($ip, $userId, $action, $token, $extra);
            
            // Use Pipeline for better performance
            Redis::pipeline(function ($pipe) use ($logData) {
                self::addIpUserAccessLogToPipeline($pipe, $logData);
            });
            
            // Log critical events to Laravel log
            if (in_array($action, ['blacklisted', 'new_user_access'])) {
                \Log::info("IP user access event: {$action}", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log IP user access: " . $e->getMessage());
        }
    }
} 