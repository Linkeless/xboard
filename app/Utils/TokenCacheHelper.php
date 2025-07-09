<?php

namespace App\Utils;

use App\Exceptions\ApiException;
use Illuminate\Support\Facades\Redis;

class TokenCacheHelper
{
    /**
     * Cache valid token to Redis for 365 days and record access
     *
     * @param string $token
     * @param \App\Models\User $user
     * @param \Illuminate\Http\Request $request
     * @param string $ip
     * @return void
     */
    public static function cacheValidToken($token, $user, $request, $ip)
    {
        try {
            $currentTime = time();
            $currentDateTime = date('Y-m-d H:i:s', $currentTime);
            
            // Prepare cache data
            $cacheData = self::prepareCacheData($token, $user, $currentTime, $currentDateTime);
            
            // Execute Redis operations
            self::executeCacheOperations($token, $cacheData);
                
        } catch (\Exception $e) {
            \Log::error("Failed to cache valid token: " . $e->getMessage(), [
                'token' => substr($token, 0, 8) . '...',
                'user_id' => $user->id,
                'ip' => $ip,
                'exception' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Prepare cache data for token
     *
     * @param string $token
     * @param \App\Models\User $user
     * @param int $currentTime
     * @param string $currentDateTime
     * @return array
     */
    public static function prepareCacheData($token, $user, $currentTime, $currentDateTime)
    {
        $tokenCacheKey = "valid_token:{$token}";
        $existingData = Redis::get($tokenCacheKey);
        
        if (!$existingData) {
            return self::createNewTokenCacheData($user, $currentTime, $currentDateTime);
        } else {
            return self::updateExistingTokenCacheData($existingData, $currentTime, $currentDateTime);
        }
    }

    /**
     * Create new token cache data
     *
     * @param \App\Models\User $user
     * @param int $currentTime
     * @param string $currentDateTime
     * @return array
     */
    public static function createNewTokenCacheData($user, $currentTime, $currentDateTime)
    {
        return [
            'tokenInfo' => [
                'user_id' => $user->id,
                'user_email' => $user->email,
                'first_verified' => $currentTime,
                'first_verified_datetime' => $currentDateTime,
                'last_access' => $currentTime,
                'last_access_datetime' => $currentDateTime,
                'total_access_count' => 1,
                'created_at' => $currentTime
            ],
            'action' => 'first_cache',
            'extraData' => ['cache_duration_days' => 365]
        ];
    }

    /**
     * Update existing token cache data
     *
     * @param string $existingData
     * @param int $currentTime
     * @param string $currentDateTime
     * @return array
     */
    public static function updateExistingTokenCacheData($existingData, $currentTime, $currentDateTime)
    {
        $tokenInfo = json_decode($existingData, true);
        $tokenInfo['last_access'] = $currentTime;
        $tokenInfo['last_access_datetime'] = $currentDateTime;
        $tokenInfo['total_access_count'] = ($tokenInfo['total_access_count'] ?? 0) + 1;
        
        return [
            'tokenInfo' => $tokenInfo,
            'action' => 'cache_updated',
            'extraData' => ['total_access_count' => $tokenInfo['total_access_count']]
        ];
    }

    /**
     * Execute cache operations using Redis pipeline
     *
     * @param string $token
     * @param array $cacheData
     * @return void
     */
    public static function executeCacheOperations($token, $cacheData)
    {
        $tokenCacheKey = "valid_token:{$token}";
        $cacheExpiry = 365 * 24 * 60 * 60; // 365 days
        
        // Prepare cache log data
        $cacheLogData = [
            'token' => $token,
            'user_id' => $cacheData['tokenInfo']['user_id'],
            'user_email' => $cacheData['tokenInfo']['user_email'],
            'action' => $cacheData['action'],
            'timestamp' => time(),
            'datetime' => date('Y-m-d H:i:s'),
            'extra' => $cacheData['extraData'],
        ];
        
        Redis::pipeline(function ($pipe) use (
            $tokenCacheKey, $cacheData, $cacheExpiry,
            $cacheLogData
        ) {
            // Cache/update token info
            $pipe->setex($tokenCacheKey, $cacheExpiry, json_encode($cacheData['tokenInfo']));
            
            // Add cache log
            self::addTokenCacheLogToPipeline($pipe, $cacheLogData);
        });
    }

    /**
     * Check token cache for existing valid token
     *
     * @param string $token
     * @param int $userId
     * @return \App\Models\User|null
     */
    public static function checkTokenCache($token, $userId)
    {
        try {
            $tokenCacheKey = "valid_token:{$token}";
            $cachedTokenData = Redis::get($tokenCacheKey);
            
            if (!$cachedTokenData) {
                return null;
            }
            
            $tokenInfo = json_decode($cachedTokenData, true);
            $cachedUserId = $tokenInfo['user_id'] ?? null;
            
            if ($cachedUserId && $cachedUserId == $userId) {
                $user = \App\Models\User::find($cachedUserId);
                if ($user) {
                    self::logTokenCache($token, $user, 'cache_hit', [
                        'cached_user_id' => $user->id,
                        'total_access_count' => $tokenInfo['total_access_count'] ?? 'unknown'
                    ]);
                    return $user;
                }
            }
            
            // Cache data is invalid, remove it
            Redis::del($tokenCacheKey);
            return null;
            
        } catch (\Exception $e) {
            \Log::error("Failed to check token cache: " . $e->getMessage(), [
                'token' => substr($token, 0, 8) . '...',
                'user_id' => $userId
            ]);
            return null;
        }
    }

    /**
     * Check if token is disabled due to security violations
     *
     * @param string $token
     * @throws ApiException
     */
    public static function checkTokenDisabled($token)
    {
        try {
            $disabledTokenKey = "disabled_token:{$token}";
            $disabledTokenData = Redis::get($disabledTokenKey);

            if ($disabledTokenData) {
                $disabledInfo = json_decode($disabledTokenData, true);
                $reason = $disabledInfo['reason'] ?? 'unknown';
                $disabledAt = $disabledInfo['disabled_at'] ?? 0;
                $expiresAt = $disabledInfo['expires_at'] ?? 0;
                $triggeringIp = $disabledInfo['triggering_ip'] ?? 'unknown';

                if ($disabledAt > 0 && $expiresAt > 0 && time() < $expiresAt) {
                    self::logTokenCache($token, null, 'disabled_token_access_attempt', [
                        'disabled_at' => $disabledAt,
                        'expires_at' => $expiresAt,
                        'reason' => $reason,
                        'triggering_ip' => $triggeringIp,
                        'current_ip' => TokenIPAccessHelper::getOriginalIp(),
                        'remaining_disabled_time' => $expiresAt - time()
                    ]);
                    
                    // Provide error code based on the reason
                    $errorCode = match($reason) {
                        'too_many_ips_5min' => '1012',
                        'too_many_ips_24h' => '1011',
                        default => '1014'
                    };
                    
                    throw new ApiException('Access Denied(' . $errorCode . ')', 200);
                }
            }
        } catch (ApiException $e) {
            throw $e; // Re-throw ApiException
        } catch (\Exception $e) {
            \Log::error("Failed to check token disabled status: " . $e->getMessage(), [
                'token' => substr($token, 0, 8) . '...',
                'exception' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Log token cache events
     *
     * @param string $token
     * @param \App\Models\User|null $user
     * @param string $action
     * @param array $extra
     * @return void
     */
    public static function logTokenCache($token, $user, $action, $extra = [])
    {
        try {
            $logData = self::createTokenCacheLogData($token, $user, $action, time(), $extra);
            
            // Use Pipeline for better performance
            Redis::pipeline(function ($pipe) use ($logData) {
                self::addTokenCacheLogToPipeline($pipe, $logData);
            });
            
            // Log cache events to Laravel log
            if (in_array($action, ['first_cache', 'cache_invalidated', 'cache_deleted'])) {
                \Log::warning("Token cache event: {$action}", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log token cache: " . $e->getMessage());
        }
    }

    /**
     * Create token cache log data
     *
     * @param string $token
     * @param \App\Models\User|null $user
     * @param string $action
     * @param int $timestamp
     * @param array $extra
     * @return array
     */
    public static function createTokenCacheLogData($token, $user, $action, $timestamp, $extra = [])
    {
        return [
            'token' => $token,
            'user_id' => $user ? $user->id : null,
            'user_email' => $user ? $user->email : null,
            'action' => $action,
            'timestamp' => $timestamp,
            'datetime' => date('Y-m-d H:i:s', $timestamp),
            'extra' => $extra,
        ];
    }

    /**
     * Add token cache log to pipeline
     *
     * @param object $pipe
     * @param array $logData
     * @return void
     */
    public static function addTokenCacheLogToPipeline($pipe, $logData)
    {
        $logKey = "token_cache_log";
        $pipe->lpush($logKey, json_encode($logData));
        $pipe->ltrim($logKey, 0, 1999);
        $pipe->expire($logKey, 30 * 24 * 60 * 60);
    }
} 