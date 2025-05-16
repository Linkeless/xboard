<?php

namespace App\Http\Middleware;

use App\Exceptions\ApiException;
use App\Utils\CacheKey;
use Closure;
use App\Models\User;
use Illuminate\Support\Facades\Cache;

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
            // Increment failed attempts counter
            $this->incrementFailedAttempts($failedKey);
            throw new ApiException('token is null',403);
        }
        
        $user = User::where('token', $token)->first();
        if (!$user) {
            // Increment failed attempts counter
            $this->incrementFailedAttempts($failedKey);
            throw new ApiException('token is error',403);
        }
        
        // Reset failed attempts counter on successful token validation
        Cache::forget($failedKey);

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
