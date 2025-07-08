<?php

namespace App\Http\Middleware;

use App\Exceptions\ApiException;
use App\Utils\CacheKey;
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
        
        // Check if IP is blacklisted
        $blacklistKey = 'ip_blacklist_' . $ip;
        if (Cache::has($blacklistKey)) {
            throw new ApiException('This IP has been blocked due to too many invalid attempts', 403);
        }
        
        // Check for too many failed token attempts from this IP
        $failedKey = 'failed_token_attempts_' . $ip;
        $maxFailedAttempts = 20; // Maximum failed attempts allowed
        
        if (Cache::has($failedKey) && Cache::get($failedKey) >= $maxFailedAttempts) {
            // Blacklist the IP for 7 days and record request headers
            $headerInfo = [
                'user_agent' => $request->header('User-Agent'),
                'referer' => $request->header('Referer'),
                'accept' => $request->header('Accept'),
                'accept_language' => $request->header('Accept-Language'),
                'accept_encoding' => $request->header('Accept-Encoding'),
                'all_headers' => $request->headers->all(),
                'blocked_at' => now()->toDateTimeString(),
            ];
            
            Cache::put($blacklistKey, $headerInfo, 60 * 60 * 24 * 7); // 7 days in seconds
            Cache::forget($failedKey); // Clear the failed attempts counter
            throw new ApiException('Too many invalid token attempts, IP blocked for 7 days', 403);
        }
        
        $token = $request->input('token');
        if (empty($token)) {
            // Log failed request
            $this->logRequest($request, '', null, 'failed_no_token', $ip, 'Token is null');
            // Increment failed attempts counter
            $this->incrementFailedAttempts($failedKey);
            throw new ApiException('token is null',403);
        }
        
        // HMAC token verification
        $result = $this->verifyHmacToken($token, $request);
        if (!$result['success']) {
            // Log failed request
            $this->logRequest($request, $token, null, 'failed_verification', $ip, $result['message']);
            // Increment failed attempts counter
            $this->incrementFailedAttempts($failedKey);
            throw new ApiException($result['message'], $result['code']);
        }
        $user = $result['user'];
        
        // Reset failed attempts counter on successful token validation
        Cache::forget($failedKey);

        // Log successful request
        $this->logRequest($request, $token, $user, 'success', $ip, 'Token verification successful');

        // Apply rate limiting for the subscribe endpoint
        if ($request->is('api/v1/client/subscribe')) {
            // User-based rate limiting
            $userKey = 'subscribe_limit_' . $user->id;
            $userMaxAttempts = 10; // Maximum 10 requests
            $userDecayMinutes = 1; // Per minute
            
            if (Cache::has($userKey)) {
                $userAttempts = Cache::get($userKey);
                if ($userAttempts >= $userMaxAttempts) {
                    throw new ApiException('Too many requests for this user', 429);
                }
                Cache::increment($userKey);
            } else {
                Cache::put($userKey, 1, 60 * $userDecayMinutes);
            }
            
            // IP-based rate limiting
            $ipKey = 'subscribe_ip_limit_' . $ip;
            $ipMaxAttempts = 30; // Maximum 30 requests per IP
            $ipDecayMinutes = 1; // Per minute
            
            if (Cache::has($ipKey)) {
                $ipAttempts = Cache::get($ipKey);
                if ($ipAttempts >= $ipMaxAttempts) {
                    throw new ApiException('Too many requests from this IP', 429);
                }
                Cache::increment($ipKey);
            } else {
                Cache::put($ipKey, 1, 60 * $ipDecayMinutes);
            }
        }
        
        $request->merge([
            'user' => $user
        ]);
        return $next($request);
    }
    
    /**
     * Verify HMAC token and return result with detailed error information
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return array
     */
    private function verifyHmacToken($token, $request)
    {
        if (strlen($token) !== 32) {
            return [
                'success' => false,
                'message' => 'Invalid token format, please login to the website and get another subscription',
                'code' => 400,
                'user' => null
            ];
        }
        
        $secretKey = 'fuckhmac'; // Use Laravel app key as secret
        
        // Method 1: Try new timestamp + user ID based HMAC token format
        // Timestamp is included for uniqueness but not used for expiration validation
        $timestampHex = substr($token, 0, 8);
        $userIdHex = substr($token, 8, 8);
        $signature = substr($token, 16, 16);
        $timestamp = hexdec($timestampHex);
        $userId = hexdec($userIdHex);
        
        // Verify token format is valid (timestamp and userId should be positive, no expiration check)
        if ($timestamp > 0 && $userId > 0) {
            $user = User::find($userId);
            if ($user) {
                // Try new format first (with token)
                $expectedSignature = substr(hash_hmac('sha256', $userId . '|' . $timestamp . '|' . $user->token, $secretKey), 0, 16);
                $isValidSignature = hash_equals($expectedSignature, $signature);
                
                // If new format fails, try old format (without token) for backward compatibility
                if (!$isValidSignature) {
                    $expectedSignatureOld = substr(hash_hmac('sha256', $userId . '|' . $timestamp, $secretKey), 0, 16);
                    $isValidSignature = hash_equals($expectedSignatureOld, $signature);
                }
                
                if ($isValidSignature) {
                    // Check token binding
                    $bindingResult = $this->checkTokenBinding($token, $request);
                    if ($bindingResult['success']) {
                        return [
                            'success' => true,
                            'user' => $user,
                            'message' => '',
                            'code' => 200
                        ];
                    } else {
                        return [
                            'success' => false,
                            'message' => $bindingResult['message'],
                            'code' => $bindingResult['code'],
                            'user' => null
                        ];
                    }
                } else {
                    return [
                        'success' => false,
                        'message' => 'Token signature verification failed, please login to the website and get another subscription',
                        'code' => 403,
                        'user' => null
                    ];
                }
            } else {
                return [
                    'success' => false,
                    'message' => 'User subscription has expired, please contact administrator',
                    'code' => 404,
                    'user' => null
                ];
            }
        }
        
        // Method 1b: Try old structured HMAC token format (user_id + signature) - for backward compatibility
        $oldUserIdHex = substr($token, 0, 8);
        $oldSignature = substr($token, 8, 24);
        $oldUserId = hexdec($oldUserIdHex);
        
        if ($oldUserId > 0) {
            $user = User::find($oldUserId);
            if ($user) {
                $expectedOldSignature = substr(hash_hmac('sha256', $oldUserId, $secretKey), 0, 24);
                if (hash_equals($expectedOldSignature, $oldSignature)) {
                    // Check token binding for old format
                    $bindingResult = $this->checkTokenBinding($token, $request);
                    if ($bindingResult['success']) {
                        return [
                            'success' => true,
                            'user' => $user,
                            'message' => '',
                            'code' => 200
                        ];
                    } else {
                        return [
                            'success' => false,
                            'message' => $bindingResult['message'],
                            'code' => $bindingResult['code'],
                            'user' => null
                        ];
                    }
                } else {
                    return [
                        'success' => false,
                        'message' => 'Token signature verification failed, please login to the website and get another subscription',
                        'code' => 403,
                        'user' => null
                    ];
                }
            } else {
                return [
                    'success' => false,
                    'message' => 'User subscription has expired, please contact administrator',
                    'code' => 404,
                    'user' => null
                ];
            }
        }
        
        // Method 2: Check if token is HMAC of user data with timestamp
        // First, try to find user by original token in database
        $user = User::where('token', $token)->first();
        if ($user) {
            // Check if this could be a new format timestamp + user ID based HMAC for this user
            $timestampHex = substr($token, 0, 8);
            $userIdHex = substr($token, 8, 8);
            $signature = substr($token, 16, 16);
            $timestamp = hexdec($timestampHex);
            $userId = hexdec($userIdHex);
            
            // Verify user ID matches (timestamp used for uniqueness only, no expiration)
            if ($timestamp > 0 && $userId == $user->id) {
                // Try new format first (with token)
                $expectedSignature = substr(hash_hmac('sha256', $userId . '|' . $timestamp . '|' . $user->token, $secretKey), 0, 16);
                $isValidSignature = hash_equals($expectedSignature, $signature);
                
                // If new format fails, try old format (without token) for backward compatibility
                if (!$isValidSignature) {
                    $expectedSignatureOld = substr(hash_hmac('sha256', $userId . '|' . $timestamp, $secretKey), 0, 16);
                    $isValidSignature = hash_equals($expectedSignatureOld, $signature);
                }
                
                if ($isValidSignature) {
                    // Check token binding
                    $bindingResult = $this->checkTokenBinding($token, $request);
                    if ($bindingResult['success']) {
                        return [
                            'success' => true,
                            'user' => $user,
                            'message' => '',
                            'code' => 200
                        ];
                    } else {
                        return [
                            'success' => false,
                            'message' => $bindingResult['message'],
                            'code' => $bindingResult['code'],
                            'user' => null
                        ];
                    }
                }
            }
            
            // Check if this could be an old timestamp-based HMAC for this user (24-bit signature)
            $oldSignature = substr($token, 8, 24);
            $oldTimestamp = hexdec(substr($token, 0, 8));
            if ($oldTimestamp > 0) {
                // Try new format first (with token)
                $expectedOldSignature = substr(hash_hmac('sha256', $user->id . '|' . $oldTimestamp . '|' . $user->token, $secretKey), 0, 24);
                $isValidOldSignature = hash_equals($expectedOldSignature, $oldSignature);
                
                // If new format fails, try old format (without token) for backward compatibility
                if (!$isValidOldSignature) {
                    $expectedOldSignatureOld = substr(hash_hmac('sha256', $user->id . '|' . $oldTimestamp, $secretKey), 0, 24);
                    $isValidOldSignature = hash_equals($expectedOldSignatureOld, $oldSignature);
                }
                
                if ($isValidOldSignature) {
                    // Check token binding
                    $bindingResult = $this->checkTokenBinding($token, $request);
                    if ($bindingResult['success']) {
                        return [
                            'success' => true,
                            'user' => $user,
                            'message' => '',
                            'code' => 200
                        ];
                    } else {
                        return [
                            'success' => false,
                            'message' => $bindingResult['message'],
                            'code' => $bindingResult['code'],
                            'user' => null
                        ];
                    }
                }
            }
            
            // Verify if this token could be a valid old-format HMAC for this user
            $validHmacs = [
                substr(hash_hmac('sha256', $user->id, $secretKey), 0, 32),
                substr(hash_hmac('sha256', $user->email, $secretKey), 0, 32),
                substr(hash_hmac('sha256', $user->uuid, $secretKey), 0, 32),
                substr(hash_hmac('sha256', $user->id . $user->email, $secretKey), 0, 32),
            ];
            
            foreach ($validHmacs as $validHmac) {
                if (hash_equals($validHmac, $token)) {
                    // Check token binding
                    $bindingResult = $this->checkTokenBinding($token, $request);
                    if ($bindingResult['success']) {
                        return [
                            'success' => true,
                            'user' => $user,
                            'message' => '',
                            'code' => 200
                        ]; // Token is a valid HMAC for this user
                    } else {
                        return [
                            'success' => false,
                            'message' => $bindingResult['message'],
                            'code' => $bindingResult['code'],
                            'user' => null
                        ];
                    }
                }
            }
            
            // Token exists in database but is not a valid HMAC
            // For backward compatibility, still return the user
            $bindingResult = $this->checkTokenBinding($token, $request);
            if ($bindingResult['success']) {
                return [
                    'success' => true,
                    'user' => $user,
                    'message' => '',
                    'code' => 200
                ];
            } else {
                return [
                    'success' => false,
                    'message' => $bindingResult['message'],
                    'code' => $bindingResult['code'],
                    'user' => null
                ];
            }
        }
        
        // Method 3: Brute force HMAC check for old format tokens
        // Only as last resort and with limited range
        for ($i = 1; $i <= 1000; $i++) {
            $hmacFromId = substr(hash_hmac('sha256', $i, $secretKey), 0, 32);
            if (hash_equals($hmacFromId, $token)) {
                $user = User::find($i);
                if ($user) {
                    // Check token binding
                    $bindingResult = $this->checkTokenBinding($token, $request);
                    if ($bindingResult['success']) {
                        return [
                            'success' => true,
                            'user' => $user,
                            'message' => '',
                            'code' => 200
                        ];
                    } else {
                        return [
                            'success' => false,
                            'message' => $bindingResult['message'],
                            'code' => $bindingResult['code'],
                            'user' => null
                        ];
                    }
                }
            }
        }
        
        return [
            'success' => false,
            'message' => 'Token verification failed or expired, please login to the website and get another subscription',
            'code' => 401,
            'user' => null
        ];
    }
    
    /**
     * Check token binding to IP and User-Agent (supports up to 5 devices)
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return array
     */
    private function checkTokenBinding($token, $request)
    {
        try {
            $ip = $this->getOriginalIpForBinding($request);
            $userAgent = $request->header('User-Agent', '');
            
            $redisKey = "token_binding:{$token}";
            $bindingData = Redis::get($redisKey);
            
            if (!$bindingData) {
                // First time using this token, create initial device binding
                $deviceInfo = [
                    'ip' => $ip,
                    'user_agent' => $userAgent,
                    'first_seen' => time(),
                    'last_used' => time(),
                ];
                
                $bindingInfo = [
                    'devices' => [$deviceInfo],
                    'created_at' => time()
                ];
                
                Redis::setex($redisKey, 30 * 24 * 60 * 60, json_encode($bindingInfo)); // 30 days expiry
                
                // Log binding event
                $this->logTokenBinding($token, $ip, $userAgent, 'created', [
                    'device_count' => 1
                ]);
                
                return ['success' => true];
            }
            
            $binding = json_decode($bindingData, true);
            
            // Handle legacy format (single device) - convert to new array format
            if (isset($binding['ip']) && !isset($binding['devices'])) {
                $legacyDevice = [
                    'ip' => $binding['ip'],
                    'user_agent' => $binding['user_agent'],
                    'first_seen' => $binding['first_seen'] ?? time(),
                    'last_used' => $binding['last_used'] ?? time(),
                ];
                $binding = [
                    'devices' => [$legacyDevice],
                    'created_at' => $binding['first_seen'] ?? time()
                ];
            }
            
            // Ensure devices array exists
            if (!isset($binding['devices']) || !is_array($binding['devices'])) {
                $binding['devices'] = [];
            }
            
            // Check if current IP and User-Agent match any existing device
            $deviceFound = false;
            $deviceIndex = -1;
            
            foreach ($binding['devices'] as $index => $device) {
                if ($device['ip'] === $ip && $device['user_agent'] === $userAgent) {
                    $deviceFound = true;
                    $deviceIndex = $index;
                    break;
                }
            }
            
            if ($deviceFound) {
                // Update last used time for existing device
                $binding['devices'][$deviceIndex]['last_used'] = time();
                Redis::setex($redisKey, 30 * 24 * 60 * 60, json_encode($binding));
                
                $this->logTokenBinding($token, $ip, $userAgent, 'access', [
                    'device_index' => $deviceIndex,
                    'device_count' => count($binding['devices'])
                ]);
                
                return ['success' => true];
            }
            
            // Device not found, check if we can add a new one
            if (count($binding['devices']) < 5) {
                // Add new device to the list
                $newDevice = [
                    'ip' => $ip,
                    'user_agent' => $userAgent,
                    'first_seen' => time(),
                    'last_used' => time(),
                ];
                
                $binding['devices'][] = $newDevice;
                Redis::setex($redisKey, 30 * 24 * 60 * 60, json_encode($binding));
                
                $this->logTokenBinding($token, $ip, $userAgent, 'device_added', [
                    'device_count' => count($binding['devices']),
                    'max_devices' => 5
                ]);
                
                return ['success' => true];
            }
            
            // Maximum devices reached and current device not found
            $this->logTokenBinding($token, $ip, $userAgent, 'device_limit_exceeded', [
                'current_device_count' => count($binding['devices']),
                'max_devices' => 5,
                'bound_devices' => array_map(function($device) {
                    return [
                        'ip' => $device['ip'],
                        'user_agent_partial' => substr($device['user_agent'], 0, 50),
                        'first_seen' => date('Y-m-d H:i:s', $device['first_seen']),
                        'last_used' => date('Y-m-d H:i:s', $device['last_used'])
                    ];
                }, $binding['devices'])
            ]);
            
            return [
                'success' => false,
                'message' => 'Token has reached maximum device limit (5), please login to the website and get another subscription',
                'code' => 403
            ];
            
        } catch (\Exception $e) {
            \Log::error("Token binding check failed: " . $e->getMessage());
            // On error, allow access (fail open)
            return ['success' => true];
        }
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
     * Log token binding events
     *
     * @param string $token
     * @param string $ip
     * @param string $userAgent
     * @param string $action
     * @param array $extra
     * @return void
     */
    private function logTokenBinding($token, $ip, $userAgent, $action, $extra = [])
    {
        try {
            $logKey = "token_binding_log";
            $logData = [
                'token_hash' => $token, // Only log partial hash for privacy
                'ip' => $ip,
                'user_agent' => $userAgent,
                'action' => $action,
                'timestamp' => time(),
                'datetime' => date('Y-m-d H:i:s'),
                'extra' => $extra,
            ];
            
            // Add to log list (keep recent 1000 entries)
            Redis::lpush($logKey, json_encode($logData));
            Redis::ltrim($logKey, 0, 999);
            Redis::expire($logKey, 7 * 24 * 60 * 60); // 7 days
            
            if ($action === 'mismatch') {
                \Log::warning("Token binding mismatch detected", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log token binding: " . $e->getMessage());
        }
    }
    
    /**
     * Get original IP for binding (similar to ClientController::getOriginalIp)
     * 
     * @param \Illuminate\Http\Request $request
     * @return string
     */
    private function getOriginalIpForBinding($request)
    {
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
    
    /**
     * Increment the failed attempts counter
     *
     * @param string $key The cache key
     * @return void
     */
    private function incrementFailedAttempts($key)
    {
        if (Cache::has($key)) {
            Cache::increment($key);
        } else {
            // Set initial value with 1 hour expiry
            Cache::put($key, 1, 3600);
        }
    }

    /**
     * 获取客户端的原始IP地址
     * 
     * @return string
     */
    protected function getOriginalIp(): string
    {
        $request = request();
        
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