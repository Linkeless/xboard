<?php

namespace App\Http\Middleware;

use App\Exceptions\ApiException;
use App\Utils\Helper;
use App\Utils\HmacHelper;
use App\Utils\RateLimitHelper;
use App\Utils\TokenIPAccessHelper;
use App\Utils\TokenCacheHelper;
use App\Utils\RequestLogHelper;
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
        $ip = TokenIPAccessHelper::getOriginalIp($request);
        
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
            RequestLogHelper::logRequest($request, '', null, 'failed_no_token', $ip, 'Token is null');
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
            RequestLogHelper::logRequest($request, $token, null, 'failed_verification', $ip, $e->getMessage());
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
        RateLimitHelper::checkIpUserAccess($ip, $user->id, $token);

        // Cache valid token to Redis for 365 days and record access
        TokenCacheHelper::cacheValidToken($token, $user, $request, $ip);

        // Log successful request
        RequestLogHelper::logRequest($request, $token, $user, 'success', $ip, 'Token verification successful');
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
        RateLimitHelper::applyEndpointRateLimiting($request, $user, $ip);
    }
    
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
        TokenCacheHelper::checkTokenDisabled($token);
        
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
        if (!HmacHelper::parseToken($token)) {
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
        $cachedUser = TokenCacheHelper::checkTokenCache($token, $tokenData['userId']);
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
        return HmacHelper::parseToken($token);
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
        $validation = HmacHelper::validateTimestampDetailed($timestamp);
        
        if (!$validation['valid']) {
            if ($validation['error_type'] === 'expired') {
                throw new ApiException('Access Denied(1004)', 200); // Token expired
            } else {
                throw new ApiException('Access Denied(1005)', 200); // Invalid timestamp (future)
            }
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
        
        // Use HmacHelper's complete token verification
        $verifiedTokenData = HmacHelper::verifyToken($token, $user->token);
        if ($verifiedTokenData) {
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
     * Validate token access by checking IP limits
     *
     * @param string $token
     * @param \Illuminate\Http\Request $request
     * @return void
     * @throws ApiException
     */
    private function validateTokenAccess($token, $request)
    {
        TokenIPAccessHelper::checkTokenIpAccess($token, $request);
    }
}