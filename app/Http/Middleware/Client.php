<?php

namespace App\Http\Middleware;

use App\Exceptions\ApiException;
use Closure;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Redis;

class Client
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $ip = $this->getOriginalIp();
        
        // Basic security checks
        $this->performBasicSecurityChecks($request, $ip);
        
        // Token verification and user authentication
        $token = $this->extractAndValidateToken($request, $ip);
        $user = $this->authenticateToken($token, $request, $ip);
        
        // Security validations
        $this->performSecurityValidations($ip, $user, $token, $request);
        
        // Rate limiting for specific endpoints
        $this->applyEndpointRateLimiting($request, $user, $ip);
        
        // Add user to request and continue
        $request->merge(['user' => $user]);
        return $next($request);
    }
    
    /**
     * Perform basic security checks
     *
     * @param \Illuminate\Http\Request $request
     * @param string $ip
     * @return void
     * @throws ApiException
     */
    private function performBasicSecurityChecks($request, $ip)
    {
        // Check if IP is blacklisted
        $blacklistKey = 'ip_blacklist:' . $ip;
        if (Redis::exists($blacklistKey)) {
            throw new ApiException('Access Denied(1008)', 200);
        }
    }
    
    /**
     * Extract and validate token from request
     *
     * @param \Illuminate\Http\Request $request
     * @param string $ip
     * @return string
     * @throws ApiException
     */
    private function extractAndValidateToken($request, $ip)
    {
        $token = $request->input('token');
        
        if (empty($token)) {
            $this->logRequest($request, '', null, 'failed_no_token', $ip, 'Token is null');
            throw new ApiException('Access Denied(1001)', 200);
        }
        
        return $token;
    }
    
    /**
     * Authenticate token and return user
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @param string $ip
     * @return \App\Models\User
     * @throws ApiException
     */
    private function authenticateToken($token, $request, $ip)
    {
        try {
            return $this->verifyHmacToken($token, $request);
        } catch (ApiException $e) {
            $this->logRequest($request, $token, null, 'failed_verification', $ip, $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Perform security validations
     *
     * @param string $ip
     * @param \App\Models\User $user
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return void
     * @throws ApiException
     */
    private function performSecurityValidations($ip, $user, $token, $request)
    {
        // Check and update IP user access tracking
        $this->checkIpUserAccess($ip, $user->id);

        // Cache valid token to Redis for 365 days and record access
        $this->cacheValidToken($token, $user, $request, $ip);

        // Log successful request
        $this->logRequest($request, $token, $user, 'success', $ip, 'Token verification successful');
    }
    
    /**
     * Apply rate limiting for specific endpoints
     *
     * @param \Illuminate\Http\Request $request
     * @param \App\Models\User $user
     * @param string $ip
     * @return void
     * @throws ApiException
     */
    private function applyEndpointRateLimiting($request, $user, $ip)
    {
        if ($request->is('api/v1/client/subscribe')) {
            $this->applySubscribeRateLimiting($user, $ip);
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
    private function applySubscribeRateLimiting($user, $ip)
    {
        // User-based rate limiting
        $this->checkUserRateLimit($user->id, 10, 1); // 10 requests per minute
        
        // IP-based rate limiting
        $this->checkIpRateLimit($ip, 30, 1); // 30 requests per minute
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
    private function checkUserRateLimit($userId, $maxAttempts, $decayMinutes)
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
    private function checkIpRateLimit($ip, $maxAttempts, $decayMinutes)
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
    
    // Token validation constants
    private const TOKEN_LENGTH = 32;
    private const TIMESTAMP_HEX_LENGTH = 8;
    private const USER_ID_HEX_LENGTH = 8;
    private const SIGNATURE_LENGTH = 16;
    private const SECRET_KEY = 'fuckhmac';
    
    /**
     * Verify HMAC token and return user or throw exception
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return \App\Models\User
     * @throws ApiException
     */
    private function verifyHmacToken($token, $request)
    {
        $this->validateTokenFormat($token);
        
        // Check if token is disabled due to security violations
        $this->checkTokenDisabled($token);
        
        // Verify token format (timestamp + userId + signature)
        $user = $this->tryTokenFormat($token);
        if ($user) {
            $this->validateTokenAccess($token, $request);
            return $user;
        }
        
        throw new ApiException('Access Denied(1003)', 200);
    }
    
    /**
     * Validate basic token format
     *
     * @param string $token
     * @throws ApiException
     */
    private function validateTokenFormat($token)
    {
        if (strlen($token) !== self::TOKEN_LENGTH) {
            throw new ApiException('Access Denied(1002)', 200);
        }
    }
    
    /**
     * Try to verify token format (timestamp + userId + signature)
     *
     * @param string $token
     * @return \App\Models\User|null
     * @throws ApiException
     */
    private function tryTokenFormat($token)
    {
        // Parse token components
        $tokenData = $this->parseTokenFormat($token);
        if (!$tokenData) {
            return null;
        }
        
        // Check cache first for performance
        $cachedUser = $this->checkTokenCache($token, $tokenData['userId']);
        if ($cachedUser) {
            return $cachedUser;
        }
        
        // Validate token timestamp
        $this->validateTokenTimestamp($tokenData['timestamp']);
        
        // Verify signature and return user
        return $this->verifyTokenSignature($token, $tokenData);
    }
    
    /**
     * Parse token format and extract components
     *
     * @param string $token
     * @return array|null
     */
    private function parseTokenFormat($token)
    {
        $timestampHex = substr($token, 0, self::TIMESTAMP_HEX_LENGTH);
        $userIdHex = substr($token, self::TIMESTAMP_HEX_LENGTH, self::USER_ID_HEX_LENGTH);
        $signature = substr($token, self::TIMESTAMP_HEX_LENGTH + self::USER_ID_HEX_LENGTH, self::SIGNATURE_LENGTH);
        
        $timestamp = hexdec($timestampHex);
        $userId = hexdec($userIdHex);
        
        // Basic format validation
        if ($timestamp <= 0 || $userId <= 0) {
            return null;
        }
        
        return [
            'timestamp' => $timestamp,
            'userId' => $userId,
            'signature' => $signature
        ];
    }
    
    /**
     * Check token cache for existing valid token
     *
     * @param string $token
     * @param int $userId
     * @return \App\Models\User|null
     */
    private function checkTokenCache($token, $userId)
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
                $user = $this->findUser($cachedUserId);
                if ($user) {
                    $this->logTokenCacheHit($token, $user, $tokenInfo);
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
     * Log token cache hit
     *
     * @param string $token
     * @param \App\Models\User $user
     * @param array $tokenInfo
     * @return void
     */
    private function logTokenCacheHit($token, $user, $tokenInfo)
    {
        $this->logTokenCache($token, $user, 'cache_hit', [
            'cached_user_id' => $user->id,
            'total_access_count' => $tokenInfo['total_access_count'] ?? 'unknown'
        ]);
    }
    
    /**
     * Validate token timestamp (24-hour expiry)
     *
     * @param int $timestamp
     * @return void
     * @throws ApiException
     */
    private function validateTokenTimestamp($timestamp)
    {
        $currentTime = time();
        $tokenAge = $currentTime - $timestamp;
        $maxAge = 24 * 60 * 60; // 24 hours in seconds
        
        // Check if token has expired
        if ($tokenAge > $maxAge) {
            throw new ApiException('Access Denied(1004)', 200);
        }
        
        // Check if token timestamp is from the future (with 5 minutes tolerance)
        if ($tokenAge < -300) { // -300 seconds = -5 minutes
            throw new ApiException('Access Denied(1005)', 200);
        }
    }
    
    /**
     * Verify token signature
     *
     * @param string $token
     * @param array $tokenData
     * @return \App\Models\User
     * @throws ApiException
     */
    private function verifyTokenSignature($token, $tokenData)
    {
        $user = $this->findUser($tokenData['userId']);
        if (!$user) {
            return null;
        }
        
        // Verify signature with user token
        if ($this->verifySignature($tokenData['userId'] . '|' . $tokenData['timestamp'] . '|' . $user->token, $tokenData['signature'])) {
            return $user;
        }
        
        throw new ApiException('Access Denied(1006)', 200);
    }
    

    
    /**
     * Find user by ID with proper error handling
     *
     * @param int $userId
     * @return \App\Models\User|null
     * @throws ApiException
     */
    private function findUser($userId)
    {
        $user = User::find($userId);
        if (!$user) {
            throw new ApiException('Access Denied(1007)', 200);
        }
        return $user;
    }
    
    /**
     * Verify HMAC signature
     *
     * @param string $data
     * @param string $signature
     * @return bool
     */
    private function verifySignature($data, $signature)
    {
        $expectedSignature = substr(hash_hmac('sha256', $data, self::SECRET_KEY), 0, self::SIGNATURE_LENGTH);
        return hash_equals($expectedSignature, $signature);
    }

    
    /**
     * Validate token access by checking IP limits
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return void
     * @throws ApiException
     */
    private function validateTokenAccess($token, $request)
    {
        $this->checkTokenIpAccess($token, $request);
    }

    /**
     * Check token IP access limits (24h: max 15 IPs, 5min: max 10 IPs)
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return void
     * @throws ApiException
     */
    private function checkTokenIpAccess($token, $request)
    {
        try {
            $ip = $this->getOriginalIp($request);
            $currentTime = time();
            $redisKey = "token_ip_access:{$token}";
            
            // Get or initialize token IP access data
            $accessInfo = $this->getOrInitializeTokenIpAccess($token, $ip, $redisKey, $currentTime);
            if ($accessInfo === null) {
                return; // First access already handled
            }
            
            // Clean up old IP entries
            $this->cleanupOldIpEntries($accessInfo, $currentTime);
            
            // Process current IP access
            if ($this->isExistingIp($accessInfo, $ip)) {
                $this->updateExistingIpAccess($accessInfo, $ip, $currentTime);
            } else {
                $this->handleNewIpAccess($token, $accessInfo, $ip, $currentTime, $redisKey);
            }
            
            // Save updated access info and log
            $this->saveTokenIpAccessAndLog($token, $redisKey, $accessInfo, $ip, $currentTime);
            
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
    private function getOrInitializeTokenIpAccess($token, $ip, $redisKey, $currentTime)
    {
        $accessData = Redis::get($redisKey);
        
        if (!$accessData) {
            $this->initializeFirstTokenAccess($token, $ip, $redisKey, $currentTime);
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
    private function initializeFirstTokenAccess($token, $ip, $redisKey, $currentTime)
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
        
        $logData = $this->createTokenIpLogData($token, $ip, 'first_access', $currentTime, [
            'total_ips' => 1
        ]);
        
        Redis::pipeline(function ($pipe) use ($redisKey, $ipAccessInfo, $logData) {
            $pipe->setex($redisKey, 30 * 24 * 60 * 60, json_encode($ipAccessInfo));
            $this->addTokenIpLogToPipeline($pipe, $logData);
        });
    }
    
    /**
     * Clean up old IP entries (older than 24 hours)
     *
     * @param array &$accessInfo
     * @param int $currentTime
     * @return void
     */
    private function cleanupOldIpEntries(&$accessInfo, $currentTime)
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
    private function isExistingIp($accessInfo, $ip)
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
    private function updateExistingIpAccess(&$accessInfo, $ip, $currentTime)
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
    private function handleNewIpAccess($token, &$accessInfo, $ip, $currentTime, $redisKey)
    {
        // Check 24-hour limit
        $this->check24HourIpLimit($token, $accessInfo, $ip, $redisKey);
        
        // Check 5-minute limit
        $this->check5MinuteIpLimit($token, $accessInfo, $ip, $currentTime, $redisKey);
        
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
    private function check24HourIpLimit($token, $accessInfo, $ip, $redisKey)
    {
        $ipsIn24Hours = count($accessInfo['ips']);
        
        if ($ipsIn24Hours >= 15) {
            $this->deleteTokenAndLog($token, $ip, $redisKey, 'too_many_ips_24h', [
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
    private function check5MinuteIpLimit($token, $accessInfo, $ip, $currentTime, $redisKey)
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
            $this->deleteTokenAndLog($token, $ip, $redisKey, 'too_many_ips_5min', [
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
    private function deleteTokenAndLog($token, $ip, $redisKey, $reason, $extraData)
    {
        $validTokenKey = "valid_token:{$token}";
        $disabledTokenKey = "disabled_token:{$token}";
        $logData = array_merge(['reason' => $reason, 'current_ip' => $ip], $extraData);
        $cacheLogData = array_merge(['reason' => $reason, 'current_ip' => $ip], $extraData, [
            'message' => "Token cache deleted due to {$reason}"
        ]);
        
        // Calculate remaining time until token's 24-hour expiry
        $tokenData = $this->parseTokenFormat($token);
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
            $ipLogData = $this->createTokenIpLogData($token, $ip, "token_deleted_{$logData['reason']}", time(), $logData);
            $this->addTokenIpLogToPipeline($pipe, $ipLogData);
            
            // Log cache deletion
            $cacheLogData = $this->createTokenCacheLogData($token, null, 'cache_deleted', time(), $cacheLogData);
            $this->addTokenCacheLogToPipeline($pipe, $cacheLogData);
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
    private function saveTokenIpAccessAndLog($token, $redisKey, $accessInfo, $ip, $currentTime)
    {
        $shouldLogNewIp = $accessInfo['_log_new_ip'] ?? false;
        unset($accessInfo['_log_new_ip']); // Remove temporary flag
        
        $logData = $this->createTokenIpLogData($token, $ip, 'access_allowed', $currentTime, [
            'total_ips' => count($accessInfo['ips'])
        ]);
        
        Redis::pipeline(function ($pipe) use ($redisKey, $accessInfo, $logData, $shouldLogNewIp, $token, $ip, $currentTime) {
            // Update token IP access data
            $pipe->setex($redisKey, 30 * 24 * 60 * 60, json_encode($accessInfo));
            
            // Log new IP access if needed
            if ($shouldLogNewIp) {
                $newIpLogData = $this->createTokenIpLogData($token, $ip, 'new_ip_access', $currentTime, [
                    'total_ips_24h' => count($accessInfo['ips']),
                    'max_ips_24h' => 15,
                    'max_ips_5min' => 10
                ]);
                $this->addTokenIpLogToPipeline($pipe, $newIpLogData);
            }
            
            // Log access allowed
            $this->addTokenIpLogToPipeline($pipe, $logData);
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
    private function createTokenIpLogData($token, $ip, $action, $timestamp, $extra = [])
    {
        return [
            'token_hash' => substr($token, 0, 8) . '...',
            'ip' => $ip,
            'action' => $action,
            'timestamp' => $timestamp,
            'datetime' => date('Y-m-d H:i:s', $timestamp),
            'extra' => $extra,
        ];
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
    private function createTokenCacheLogData($token, $user, $action, $timestamp, $extra = [])
    {
        return [
            'token_hash' => $token,
            'user_id' => $user ? $user->id : null,
            'user_email' => $user ? $user->email : null,
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
    private function addTokenIpLogToPipeline($pipe, $logData)
    {
        $logKey = "token_ip_access_log";
        $pipe->lpush($logKey, json_encode($logData));
        $pipe->ltrim($logKey, 0, 1999);
        $pipe->expire($logKey, 7 * 24 * 60 * 60);
    }
    
    /**
     * Add token cache log to pipeline
     *
     * @param object $pipe
     * @param array $logData
     * @return void
     */
    private function addTokenCacheLogToPipeline($pipe, $logData)
    {
        $logKey = "token_cache_log";
        $pipe->lpush($logKey, json_encode($logData));
        $pipe->ltrim($logKey, 0, 1999);
        $pipe->expire($logKey, 30 * 24 * 60 * 60);
    }
    
    /**
     * Log request events
     *
     * @param \Illuminate\Http\Request $request
     * @param string $token
     * @param \App\Models\User|null $user
     * @param string $status
     * @param string $ip
     * @param string $message
     * @return void
     */
    private function logRequest($request, $token, $user, $status, $ip, $message = '')
    {
        try {
            $logKey = "token_requests:" . ($token ?: 'null');
            $logData = [
                'token' => $token ?: 'null',
                'user_id' => $user ? $user->id : null,
                'user_email' => $user ? $user->email : null,
                'ip' => $ip,
                'user_agent' => $request->header('User-Agent', ''),
                'method' => $request->method(),
                'url' => $request->fullUrl(),
                'status' => $status,
                'message' => $message,
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'headers' => [
                    'referer' => $request->header('Referer'),
                    'accept' => $request->header('Accept'),
                    'accept_language' => $request->header('Accept-Language'),
                    'accept_encoding' => $request->header('Accept-Encoding'),
                    'cf_connecting_ip' => $request->header('CF-Connecting-IP'),
                    'x_forwarded_for' => $request->header('X-Forwarded-For'),
                ]
            ];
            
            // Add to log list (keep recent 2000 entries)
            Redis::lpush($logKey, json_encode($logData));
            Redis::ltrim($logKey, 0, 1999);
            
            // Also log to Laravel log for failed requests
            if (in_array($status, ['failed_no_token', 'failed_verification', 'failed_rate_limit'])) {
                \Log::warning("Client request failed", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log request: " . $e->getMessage());
        }
    }



    /**
     * Log IP user access events
     *
     * @param string $ip
     * @param int $userId
     * @param string $action
     * @param array $extra
     * @return void
     */
    private function logIpUserAccess($ip, $userId, $action, $extra = [])
    {
        try {
            $logKey = "ip_user_access_log";
            $logData = [
                'ip' => $ip,
                'user_id' => $userId,
                'action' => $action,
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'extra' => $extra,
            ];
            
            // Add to log list (keep recent 2000 entries)
            Redis::lpush($logKey, json_encode($logData));
            Redis::ltrim($logKey, 0, 1999);
            Redis::expire($logKey, 7 * 24 * 60 * 60); // 7 days
            
            // Log critical events to Laravel log
            if (in_array($action, ['blacklisted', 'new_user_access'])) {
                \Log::info("IP user access event: {$action}", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log IP user access: " . $e->getMessage());
        }
    }



    /**
     * Log token IP access events
     *
     * @param string $token
     * @param string $ip
     * @param string $action
     * @param array $extra
     * @return void
     */
    private function logTokenIpAccess($token, $ip, $action, $extra = [])
    {
        try {
            $logKey = "token_ip_access_log";
            $logData = [
                'token_hash' => substr($token, 0, 8) . '...', // Only log partial hash for privacy
                'ip' => $ip,
                'action' => $action,
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'extra' => $extra,
            ];
            
            // Add to log list (keep recent 2000 entries)
            Redis::lpush($logKey, json_encode($logData));
            Redis::ltrim($logKey, 0, 1999);
            Redis::expire($logKey, 7 * 24 * 60 * 60); // 7 days
            
            // Log critical events to Laravel log
            if (in_array($action, ['token_deleted_24h', 'token_deleted_5min', 'new_ip_access'])) {
                \Log::warning("Token IP access event: {$action}", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log token IP access: " . $e->getMessage());
        }
    }
    

    
    /**
     * Check and update IP user access tracking
     *
     * @param string $ip
     * @param int $userId
     * @return void
     */
    private function checkIpUserAccess($ip, $userId)
    {
        try {
            // Check if IP is in whitelist first
            if ($this->isIpWhitelisted($ip)) {
                $this->logIpUserAccess($ip, $userId, 'whitelist_access', [
                    'message' => 'IP is whitelisted, skipping access limits'
                ]);
                return; // Skip all access tracking and limits for whitelisted IPs
            }
            
            $trackingKey = 'ip_user_access:' . $ip;
            $maxDifferentUsers = 10;
            $trackingPeriod = 60 * 60 * 24; // 24 hours
            
            // Get or initialize tracking data
            $trackingData = $this->getOrInitializeIpUserTracking($trackingKey, $trackingPeriod);
            
            // Process user access
            if ($this->isNewUserForIp($trackingData, $userId)) {
                $this->handleNewUserAccess($ip, $userId, $trackingData, $maxDifferentUsers, $trackingKey);
            } else {
                $this->handleExistingUserAccess($ip, $userId, $trackingData);
            }
            
            // Update tracking data in Redis using JSON format
            Redis::setex($trackingKey, $trackingPeriod, json_encode($trackingData));
            
        } catch (\Exception $e) {
            $this->handleIpUserAccessError($e, $ip, $userId);
        }
    }
    
    /**
     * Check if IP is in whitelist
     *
     * @param string $ip
     * @return bool
     */
    private function isIpWhitelisted($ip)
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
    private function getOrInitializeIpUserTracking($trackingKey, $trackingPeriod)
    {
        try {
            $trackingDataJson = Redis::get($trackingKey);
            $trackingData = $trackingDataJson ? json_decode($trackingDataJson, true) : [];
        } catch (\Exception $e) {
            $trackingData = [];
        }
        
        $currentTime = time();
        
        // Initialize if empty or expired
        if (empty($trackingData) || $this->isTrackingDataExpired($trackingData, $currentTime, $trackingPeriod)) {
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
    private function isTrackingDataExpired($trackingData, $currentTime, $trackingPeriod)
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
    private function isNewUserForIp($trackingData, $userId)
    {
        return !in_array($userId, $trackingData['user_ids']);
    }
    
    /**
     * Handle new user access for IP
     *
     * @param string $ip
     * @param int $userId
     * @param array &$trackingData
     * @param int $maxDifferentUsers
     * @param string $trackingKey
     * @return void
     * @throws ApiException
     */
    private function handleNewUserAccess($ip, $userId, &$trackingData, $maxDifferentUsers, $trackingKey)
    {
        // Add new user to tracking
        $trackingData['user_ids'][] = $userId;
        $trackingData['last_updated'] = time();
        
        // Check if limit exceeded
        if (count($trackingData['user_ids']) >= $maxDifferentUsers) {
            $this->blacklistIpForTooManyUsers($ip, $userId, $trackingData, $maxDifferentUsers, $trackingKey);
            throw new ApiException('Access Denied(1013)', 200);
        }
        
        // Log new user access
        $this->logIpUserAccess($ip, $userId, 'new_user_access', [
            'total_users_accessed' => count($trackingData['user_ids']),
            'max_allowed' => $maxDifferentUsers
        ]);
    }
    
    /**
     * Handle existing user access for IP
     *
     * @param string $ip
     * @param int $userId
     * @param array &$trackingData
     * @return void
     */
    private function handleExistingUserAccess($ip, $userId, &$trackingData)
    {
        $trackingData['last_updated'] = time();
        
        $this->logIpUserAccess($ip, $userId, 'existing_user_access', [
            'total_users_accessed' => count($trackingData['user_ids'])
        ]);
    }
    
    /**
     * Blacklist IP for accessing too many different users
     *
     * @param string $ip
     * @param int $userId
     * @param array $trackingData
     * @param int $maxDifferentUsers
     * @param string $trackingKey
     * @return void
     */
    private function blacklistIpForTooManyUsers($ip, $userId, $trackingData, $maxDifferentUsers, $trackingKey)
    {
        $blacklistKey = 'ip_blacklist_' . $ip;
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
        
        // Cache blacklist for 7 days
        Redis::setex($blacklistKey, 60 * 60 * 24 * 7, json_encode($blacklistInfo));
        
        // Log blacklist event
        $this->logIpUserAccess($ip, $userId, 'blacklisted', [
            'user_ids_accessed' => $trackingData['user_ids'],
            'access_count' => count($trackingData['user_ids']),
            'max_allowed' => $maxDifferentUsers
        ]);
        
        // Clear tracking data since IP is now blacklisted
        Redis::del($trackingKey);
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
    private function handleIpUserAccessError($e, $ip, $userId)
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
     * Cache valid token to Redis for 365 days and record access
     *
     * @param string $token
     * @param \App\Models\User $user
     * @param \Illuminate\Http\Request $request
     * @param string $ip
     * @return void
     */
    private function cacheValidToken($token, $user, $request, $ip)
    {
        try {
            $currentTime = time();
            $currentDateTime = date('Y-m-d H:i:s', $currentTime);
            
                    // Prepare cache data
        $cacheData = $this->prepareCacheData($token, $user, $currentTime, $currentDateTime);
        
        // Execute Redis operations
        $this->executeCacheOperations($token, $cacheData);
            
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
    private function prepareCacheData($token, $user, $currentTime, $currentDateTime)
    {
        $tokenCacheKey = "valid_token:{$token}";
        $existingData = Redis::get($tokenCacheKey);
        
        if (!$existingData) {
            return $this->createNewTokenCacheData($user, $currentTime, $currentDateTime);
        } else {
            return $this->updateExistingTokenCacheData($existingData, $currentTime, $currentDateTime);
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
    private function createNewTokenCacheData($user, $currentTime, $currentDateTime)
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
    private function updateExistingTokenCacheData($existingData, $currentTime, $currentDateTime)
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
    private function executeCacheOperations($token, $cacheData)
    {
        $tokenCacheKey = "valid_token:{$token}";
        $cacheExpiry = 365 * 24 * 60 * 60; // 365 days
        
        // Prepare cache log data
        $cacheLogData = [
            'token_hash' => substr($token, 0, 8) . '...',
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
            $this->addTokenCacheLogToPipeline($pipe, $cacheLogData);
        });
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
    private function logTokenCache($token, $user, $action, $extra = [])
    {
        try {
            $logKey = "token_cache_log";
            $logData = [
                'token_hash' => $token, // Only log partial hash for privacy
                'user_id' => $user ? $user->id : null,
                'user_email' => $user ? $user->email : null,
                'action' => $action,
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'extra' => $extra,
            ];
            
            // Add to log list (keep recent 2000 entries)
            Redis::lpush($logKey, json_encode($logData));
            Redis::ltrim($logKey, 0, 1999);
            Redis::expire($logKey, 30 * 24 * 60 * 60); // 30 days
            
            // Log cache events to Laravel log
            if (in_array($action, ['first_cache', 'cache_invalidated', 'cache_deleted'])) {
                \Log::warning("Token cache event: {$action}", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log token cache: " . $e->getMessage());
        }
    }

    /**
     * Check if token is disabled due to security violations
     *
     * @param string $token
     * @throws ApiException
     */
    private function checkTokenDisabled($token)
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
                    $this->logTokenCache($token, null, 'disabled_token_access_attempt', [
                        'disabled_at' => $disabledAt,
                        'expires_at' => $expiresAt,
                        'reason' => $reason,
                        'triggering_ip' => $triggeringIp,
                        'current_ip' => $this->getOriginalIp(),
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
     * 获取客户端的原始IP地址
     * 
     * @param \Illuminate\Http\Request|null $request
     * @return string
     */
    protected function getOriginalIp($request = null): string
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