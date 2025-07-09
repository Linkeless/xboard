<?php

namespace App\Utils;

use App\Exceptions\ApiException;
use Illuminate\Support\Facades\Redis;

class TokenIPAccessHelper
{
    /**
     * Check token IP access limits (24h: max 15 IPs, 5min: max 10 IPs)
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return void
     * @throws ApiException
     */
    public static function checkTokenIpAccess($token, $request)
    {
        try {
            $ip = self::getOriginalIp($request);
            $currentTime = time();
            $redisKey = "token_ip_access:{$token}";
            
            // Get or initialize token IP access data
            $accessInfo = self::getOrInitializeTokenIpAccess($token, $ip, $redisKey, $currentTime);
            if ($accessInfo === null) {
                return; // First access already handled
            }
            
            // Clean up old IP entries
            self::cleanupOldIpEntries($accessInfo, $currentTime);
            
            // Process current IP access
            if (self::isExistingIp($accessInfo, $ip)) {
                self::updateExistingIpAccess($accessInfo, $ip, $currentTime);
            } else {
                self::handleNewIpAccess($token, $accessInfo, $ip, $currentTime, $redisKey);
            }
            
            // Save updated access info and log
            self::saveTokenIpAccessAndLog($token, $redisKey, $accessInfo, $ip, $currentTime);
            
        } catch (ApiException $e) {
            throw $e;
        } catch (\Exception $e) {
            \Log::error("Token IP access check failed: " . $e->getMessage(), [
                'token' => substr($token, 0, 8) . '...',
                'ip' => $ip ?? 'unknown',
                'exception' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Get or initialize token IP access data
     *
     * @param string $token
     * @param string $ip
     * @param string $redisKey
     * @param int $currentTime
     * @return array|null Returns null if first access is handled
     */
    public static function getOrInitializeTokenIpAccess($token, $ip, $redisKey, $currentTime)
    {
        $accessData = Redis::get($redisKey);
        
        if (!$accessData) {
            self::initializeFirstTokenAccess($token, $ip, $redisKey, $currentTime);
            return null;
        }
        
        return json_decode($accessData, true);
    }

    /**
     * Initialize first time token access
     *
     * @param string $token
     * @param string $ip
     * @param string $redisKey
     * @param int $currentTime
     * @return void
     */
    public static function initializeFirstTokenAccess($token, $ip, $redisKey, $currentTime)
    {
        $ipAccessInfo = [
            'ips' => [
                $ip => [
                    'first_seen' => $currentTime,
                    'last_seen' => $currentTime,
                    'access_count' => 1
                ]
            ],
            'created_at' => $currentTime
        ];
        
        $logData = self::createTokenIpLogData($token, $ip, 'first_access', $currentTime, [
            'total_ips' => 1
        ]);
        
        Redis::pipeline(function ($pipe) use ($redisKey, $ipAccessInfo, $logData) {
            $pipe->setex($redisKey, 30 * 24 * 60 * 60, json_encode($ipAccessInfo));
            self::addTokenIpLogToPipeline($pipe, $logData);
        });
    }

    /**
     * Clean up old IP entries (older than 24 hours)
     *
     * @param array &$accessInfo
     * @param int $currentTime
     * @return void
     */
    public static function cleanupOldIpEntries(&$accessInfo, $currentTime)
    {
        $cleanupThreshold = $currentTime - (24 * 60 * 60);
        
        foreach ($accessInfo['ips'] as $trackedIp => $ipData) {
            if ($ipData['last_seen'] < $cleanupThreshold) {
                unset($accessInfo['ips'][$trackedIp]);
            }
        }
    }

    /**
     * Check if IP already exists in access info
     *
     * @param array $accessInfo
     * @param string $ip
     * @return bool
     */
    public static function isExistingIp($accessInfo, $ip)
    {
        return isset($accessInfo['ips'][$ip]);
    }

    /**
     * Update existing IP access record
     *
     * @param array &$accessInfo
     * @param string $ip
     * @param int $currentTime
     * @return void
     */
    public static function updateExistingIpAccess(&$accessInfo, $ip, $currentTime)
    {
        $accessInfo['ips'][$ip]['last_seen'] = $currentTime;
        $accessInfo['ips'][$ip]['access_count']++;
    }

    /**
     * Handle new IP access with limit checks
     *
     * @param string $token
     * @param array &$accessInfo
     * @param string $ip
     * @param int $currentTime
     * @param string $redisKey
     * @return void
     * @throws ApiException
     */
    public static function handleNewIpAccess($token, &$accessInfo, $ip, $currentTime, $redisKey)
    {
        // Check 24-hour limit
        self::check24HourIpLimit($token, $accessInfo, $ip, $redisKey);
        
        // Check 5-minute limit
        self::check5MinuteIpLimit($token, $accessInfo, $ip, $currentTime, $redisKey);
        
        // Add new IP to tracking
        $accessInfo['ips'][$ip] = [
            'first_seen' => $currentTime,
            'last_seen' => $currentTime,
            'access_count' => 1
        ];
        
        // Mark for logging new IP access
        $accessInfo['_log_new_ip'] = true;
    }

    /**
     * Check 24-hour IP limit (max 15 IPs)
     *
     * @param string $token
     * @param array $accessInfo
     * @param string $ip
     * @param string $redisKey
     * @return void
     * @throws ApiException
     */
    public static function check24HourIpLimit($token, $accessInfo, $ip, $redisKey)
    {
        $ipsIn24Hours = count($accessInfo['ips']);
        
        if ($ipsIn24Hours >= 15) {
            self::deleteTokenAndLog($token, $ip, $redisKey, 'too_many_ips_24h', [
                'ip_count_24h' => $ipsIn24Hours,
                'current_ip' => $ip,
                'all_ips' => array_keys($accessInfo['ips'])
            ]);
            
            throw new ApiException('Access Denied(1011)', 200);
        }
    }

    /**
     * Check 5-minute IP limit (max 10 IPs)
     *
     * @param string $token
     * @param array $accessInfo
     * @param string $ip
     * @param int $currentTime
     * @param string $redisKey
     * @return void
     * @throws ApiException
     */
    public static function check5MinuteIpLimit($token, $accessInfo, $ip, $currentTime, $redisKey)
    {
        $fiveMinutesAgo = $currentTime - (5 * 60);
        $recentIpsCount = 0;
        $recentIps = [];
        
        foreach ($accessInfo['ips'] as $trackedIp => $ipData) {
            if ($ipData['first_seen'] >= $fiveMinutesAgo) {
                $recentIpsCount++;
                $recentIps[$trackedIp] = $ipData;
            }
        }
        
        if ($recentIpsCount >= 10) {
            self::deleteTokenAndLog($token, $ip, $redisKey, 'too_many_ips_5min', [
                'ip_count_5min' => $recentIpsCount,
                'current_ip' => $ip,
                'recent_ips' => $recentIps
            ]);
            
            throw new ApiException('Access Denied(1012)', 200);
        }
    }

    /**
     * Delete token and log the action
     *
     * @param string $token
     * @param string $ip
     * @param string $redisKey
     * @param string $reason
     * @param array $extraData
     * @return void
     */
    public static function deleteTokenAndLog($token, $ip, $redisKey, $reason, $extraData)
    {
        $validTokenKey = "valid_token:{$token}";
        $disabledTokenKey = "disabled_token:{$token}";
        $logData = array_merge(['reason' => $reason, 'current_ip' => $ip], $extraData);
        $cacheLogData = array_merge(['reason' => $reason, 'current_ip' => $ip], $extraData, [
            'message' => "Token cache deleted due to {$reason}"
        ]);
        
        // Calculate remaining time until token's 24-hour expiry
        $tokenData = HmacHelper::parseToken($token);
        $tokenTimestamp = $tokenData['timestamp'] ?? time();
        $tokenExpiryTime = $tokenTimestamp + (24 * 60 * 60); // 24 hours from token creation
        $remainingTime = max(0, $tokenExpiryTime - time());
        
        Redis::pipeline(function ($pipe) use ($redisKey, $validTokenKey, $disabledTokenKey, $token, $ip, $logData, $cacheLogData, $remainingTime, $reason) {
            // Delete token keys
            $pipe->del($redisKey);
            $pipe->del($validTokenKey);
            
            // Add disabled token marker that expires when the original token would expire
            if ($remainingTime > 0) {
                $disabledInfo = [
                    'disabled_at' => time(),
                    'disabled_datetime' => date('Y-m-d H:i:s'),
                    'reason' => $reason,
                    'triggering_ip' => $ip,
                    'expires_at' => $tokenTimestamp + (24 * 60 * 60),
                    'expires_datetime' => date('Y-m-d H:i:s', $tokenTimestamp + (24 * 60 * 60)),
                ];
                $pipe->setex($disabledTokenKey, $remainingTime, json_encode($disabledInfo));
            }
            
            // Log token IP access deletion
            $ipLogData = self::createTokenIpLogData($token, $ip, "token_deleted_{$logData['reason']}", time(), $logData);
            self::addTokenIpLogToPipeline($pipe, $ipLogData);
            
            // Log cache deletion
            $cacheLogData = TokenCacheHelper::createTokenCacheLogData($token, null, 'cache_deleted', time(), $cacheLogData);
            TokenCacheHelper::addTokenCacheLogToPipeline($pipe, $cacheLogData);
        });
    }

    /**
     * Save token IP access data and log
     *
     * @param string $token
     * @param string $redisKey
     * @param array $accessInfo
     * @param string $ip
     * @param int $currentTime
     * @return void
     */
    public static function saveTokenIpAccessAndLog($token, $redisKey, $accessInfo, $ip, $currentTime)
    {
        $shouldLogNewIp = $accessInfo['_log_new_ip'] ?? false;
        unset($accessInfo['_log_new_ip']); // Remove temporary flag
        
        $logData = self::createTokenIpLogData($token, $ip, 'access_allowed', $currentTime, [
            'total_ips' => count($accessInfo['ips'])
        ]);
        
        Redis::pipeline(function ($pipe) use ($redisKey, $accessInfo, $logData, $shouldLogNewIp, $token, $ip, $currentTime) {
            // Update token IP access data
            $pipe->setex($redisKey, 30 * 24 * 60 * 60, json_encode($accessInfo));
            
            // Log new IP access if needed
            if ($shouldLogNewIp) {
                $newIpLogData = self::createTokenIpLogData($token, $ip, 'new_ip_access', $currentTime, [
                    'total_ips_24h' => count($accessInfo['ips']),
                    'max_ips_24h' => 15,
                    'max_ips_5min' => 10
                ]);
                self::addTokenIpLogToPipeline($pipe, $newIpLogData);
            }
            
            // Log access allowed
            self::addTokenIpLogToPipeline($pipe, $logData);
        });
    }

    /**
     * Create token IP access log data
     *
     * @param string $token
     * @param string $ip
     * @param string $action
     * @param int $timestamp
     * @param array $extra
     * @return array
     */
    public static function createTokenIpLogData($token, $ip, $action, $timestamp, $extra = [])
    {
        return [
            'token' => $token,
            'ip' => $ip,
            'action' => $action,
            'timestamp' => $timestamp,
            'datetime' => date('Y-m-d H:i:s', $timestamp),
            'extra' => $extra,
        ];
    }

    /**
     * Add token IP log to pipeline
     *
     * @param object $pipe
     * @param array $logData
     * @return void
     */
    public static function addTokenIpLogToPipeline($pipe, $logData)
    {
        $logKey = "token_ip_access_log";
        $pipe->lpush($logKey, json_encode($logData));
        $pipe->ltrim($logKey, 0, 1999);
        $pipe->expire($logKey, 7 * 24 * 60 * 60);
    }

    /**
     * 获取客户端的原始IP地址
     * 
     * @param \Illuminate\Http\Request|null $request
     * @return string
     */
    public static function getOriginalIp($request = null): string
    {
        $request = $request ?: request();
        
        // 首先检查请求参数中是否有ip参数
        if ($request->has('ip')) {
            return $request->input('ip');
        }
        
        // 检查Cloudflare的CF-Connecting-IP头
        if ($request->header('CF-Connecting-IP')) {
            return $request->header('CF-Connecting-IP');
        }
        
        // 检查是否存在X-Forwarded-For头
        if ($request->header('X-Forwarded-For')) {
            // X-Forwarded-For格式为: "客户端IP, 代理1 IP, 代理2 IP"
            // 取第一个IP，即最原始的客户端IP
            $ips = explode(',', $request->header('X-Forwarded-For'));
            return trim($ips[0]);
        }
        
        // 尝试获取全部IP链并取第一个
        $ips = $request->ips();
        if (!empty($ips)) {
            return $ips[0];
        }
        
        // 默认回退到getClientIp方法
        return $request->getClientIp();
    }
} 