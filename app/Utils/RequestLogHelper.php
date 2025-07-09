<?php

namespace App\Utils;

use Illuminate\Support\Facades\Redis;

class RequestLogHelper
{
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
    public static function logRequest($request, $token, $user, $status, $ip, $message = '')
    {
        try {
            $logData = self::createRequestLogData($request, $token, $user, $status, $ip, $message);
            
            // Use Pipeline for better performance
            Redis::pipeline(function ($pipe) use ($logData, $token) {
                self::addRequestLogToPipeline($pipe, $logData, $token);
            });
            
            // Also log to Laravel log for failed requests
            if (in_array($status, ['failed_no_token', 'failed_verification', 'failed_rate_limit'])) {
                \Log::warning("Client request failed", $logData);
            }
            
        } catch (\Exception $e) {
            \Log::error("Failed to log request: " . $e->getMessage());
        }
    }

    /**
     * Create request log data
     *
     * @param \Illuminate\Http\Request $request
     * @param string $token
     * @param \App\Models\User|null $user
     * @param string $status
     * @param string $ip
     * @param string $message
     * @return array
     */
    public static function createRequestLogData($request, $token, $user, $status, $ip, $message = '')
    {
        return [
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
    }

    /**
     * Add request log to pipeline
     *
     * @param object $pipe
     * @param array $logData
     * @param string $token
     * @return void
     */
    public static function addRequestLogToPipeline($pipe, $logData, $token = '')
    {
        $logKey = "token_requests:" . ($token ?: 'null');
        $pipe->lpush($logKey, json_encode($logData));
        $pipe->ltrim($logKey, 0, 1999);
    }
} 