<?php

namespace App\Http\Controllers\V1\Client;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Http\JsonResponse;

class SubscriptionLogController extends Controller
{
    /**
     * Get recent subscription requests
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function getRecentRequests(Request $request): JsonResponse
    {
        $user = $request->user;
        
        // Check if user exists and has an ID
        if (!isset($user['id'])) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid user or missing authentication'
            ], 401);
        }
        
        // Get target user ID - default to current user
        $targetUserId = $request->input('user_id', $user['id']);
        $userId = $targetUserId;
        
        $redisKey = "user_requests:{$userId}";
        
        // Get the 10 most recent requests
        $logs = Redis::lrange($redisKey, 0, 9);
        
        $formattedLogs = [];
        foreach ($logs as $log) {
            $logData = json_decode($log, true);
            if ($logData) {
                $formattedLogs[] = [
                    'ip' => $logData['ip'],
                    'datetime' => $logData['datetime'],
                    'user_agent' => $logData['user_agent'],
                    'host' => $logData['request_headers']['host'] ?? 'unknown',
                ];
            }
        }
        
        // Sort by datetime descending (most recent first)
        usort($formattedLogs, function($a, $b) {
            return strtotime($b['datetime']) - strtotime($a['datetime']);
        });
        
        // Limit to 10 most recent entries
        $formattedLogs = array_slice($formattedLogs, 0, 10);
        
        return response()->json([
            'success' => true,
            'data' => [
                'user_id' => $userId,
                'total_requests' => count($formattedLogs),
                'recent_requests' => $formattedLogs
            ]
        ]);
    }
    
    /**
     * Get most active users
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function getActiveUsers(Request $request): JsonResponse
    {
        $user = $request->user;
        
        // Check if user exists and has an ID
        if (!isset($user['id'])) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid user or missing authentication'
            ], 401);
        }
        
        // Get the most active users in the last 24 hours
        $now = time();
        $oneDayAgo = $now - (24 * 60 * 60);
        
        $activeUsers = Redis::zrevrangebyscore('active_users', $now, $oneDayAgo, [
            'limit' => [0, 10],
            'withscores' => true
        ]);
        
        $userActivity = [];
        foreach ($activeUsers as $userId => $lastActivity) {
            $requestCount = Redis::llen("user_requests:{$userId}");
            $userActivity[] = [
                'user_id' => $userId,
                'last_activity' => date('Y-m-d H:i:s', $lastActivity),
                'request_count' => $requestCount
            ];
        }
        
        return response()->json([
            'success' => true,
            'data' => [
                'active_users' => $userActivity
            ]
        ]);
    }
} 