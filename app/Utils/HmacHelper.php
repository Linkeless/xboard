<?php

namespace App\Utils;

class HmacHelper
{
    // HMAC Token constants
    private const TOKEN_LENGTH = 32;
    private const TIMESTAMP_HEX_LENGTH = 8;
    private const USER_ID_HEX_LENGTH = 8;
    private const SIGNATURE_LENGTH = 16;

    /**
     * 获取用于HMAC签名的密钥
     * 
     * @return string
     */
    public static function getSecretKey(): string
    {
        return env('PHP_SHA256', 'default_secret_key');
    }

    /**
     * 生成HMAC token
     * 
     * @param int $userId 用户ID
     * @param string $userToken 用户token
     * @return string
     */
    public static function generateToken(int $userId, string $userToken): string
    {
        $secretKey = self::getSecretKey();
        $timestamp = time();
        $timestampHex = sprintf('%08x', $timestamp); // 8位十六进制时间戳
        $userIdHex = sprintf('%08x', $userId); // 8位十六进制用户ID
        $hmacSignature = substr(hash_hmac('sha256', $userId . '|' . $timestamp . '|' . $userToken, $secretKey), 0, 16); // 16位签名
        
        return $timestampHex . $userIdHex . $hmacSignature;
    }

    /**
     * 解析HMAC token格式
     *
     * @param string $token
     * @return array|null
     */
    public static function parseToken(string $token): ?array
    {
        if (strlen($token) !== self::TOKEN_LENGTH) {
            return null;
        }

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
     * 验证HMAC签名
     *
     * @param string $data
     * @param string $signature
     * @return bool
     */
    public static function verifySignature(string $data, string $signature): bool
    {
        $expectedSignature = substr(hash_hmac('sha256', $data, self::getSecretKey()), 0, self::SIGNATURE_LENGTH);
        return hash_equals($expectedSignature, $signature);
    }

    /**
     * 验证token时间戳（24小时有效期）
     *
     * @param int $timestamp
     * @return bool
     */
    public static function validateTimestamp(int $timestamp): bool
    {
        $currentTime = time();
        $tokenAge = $currentTime - $timestamp;
        $maxAge = 24 * 60 * 60; // 24 hours in seconds

        // Check if token has expired
        if ($tokenAge > $maxAge) {
            return false;
        }

        // Check if token timestamp is from the future (with 5 minutes tolerance)
        if ($tokenAge < -300) { // -300 seconds = -5 minutes
            return false;
        }

        return true;
    }

    /**
     * 验证token时间戳并返回详细结果
     *
     * @param int $timestamp
     * @return array 返回 ['valid' => bool, 'error_type' => string]
     */
    public static function validateTimestampDetailed(int $timestamp): array
    {
        $currentTime = time();
        $tokenAge = $currentTime - $timestamp;
        $maxAge = 24 * 60 * 60; // 24 hours in seconds

        // Check if token has expired
        if ($tokenAge > $maxAge) {
            return ['valid' => false, 'error_type' => 'expired'];
        }

        // Check if token timestamp is from the future (with 5 minutes tolerance)
        if ($tokenAge < -300) { // -300 seconds = -5 minutes
            return ['valid' => false, 'error_type' => 'future'];
        }

        return ['valid' => true, 'error_type' => null];
    }

    /**
     * 验证完整的HMAC token
     *
     * @param string $token
     * @param string $userToken 用户的token
     * @return array|null 返回解析后的token数据或null
     */
    public static function verifyToken(string $token, string $userToken): ?array
    {
        // 解析token格式
        $tokenData = self::parseToken($token);
        if (!$tokenData) {
            return null;
        }

        // 验证时间戳
        if (!self::validateTimestamp($tokenData['timestamp'])) {
            return null;
        }

        // 构建验证数据
        $verifyData = $tokenData['userId'] . '|' . $tokenData['timestamp'] . '|' . $userToken;

        // 验证签名
        if (!self::verifySignature($verifyData, $tokenData['signature'])) {
            return null;
        }

        return $tokenData;
    }

    /**
     * 快速验证HMAC token并返回用户ID
     *
     * @param string $token
     * @param callable $getUserTokenCallback 回调函数，接收用户ID，返回用户token
     * @return int|null 返回用户ID或null
     */
    public static function verifyTokenAndGetUserId(string $token, callable $getUserTokenCallback): ?int
    {
        // 解析token格式
        $tokenData = self::parseToken($token);
        if (!$tokenData) {
            return null;
        }

        // 验证时间戳
        if (!self::validateTimestamp($tokenData['timestamp'])) {
            return null;
        }

        // 获取用户token
        $userToken = $getUserTokenCallback($tokenData['userId']);
        if (!$userToken) {
            return null;
        }

        // 构建验证数据
        $verifyData = $tokenData['userId'] . '|' . $tokenData['timestamp'] . '|' . $userToken;

        // 验证签名
        if (!self::verifySignature($verifyData, $tokenData['signature'])) {
            return null;
        }

        return $tokenData['userId'];
    }
} 