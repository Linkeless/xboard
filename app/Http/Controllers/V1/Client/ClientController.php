<?php

namespace App\Http\Controllers\V1\Client;

use App\Http\Controllers\Controller;
use App\Protocols\General;
use App\Services\ServerService;
use App\Services\UserService;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class ClientController extends Controller
{

    // 支持hy2 的客户端版本列表
    const SupportedHy2ClientVersions = [
        'NekoBox' => '1.2.7',
        'sing-box' => '1.5.0',
        'stash' => '2.5.0',
        'Shadowrocket' => '1993',
        'ClashMetaForAndroid' => '2.9.0',
        'Nekoray' => '3.24',
        'verge' => '1.3.8',
        'ClashX Meta' => '1.3.5',
        'Hiddify' => '0.1.0',
        'loon' => '637',
        'v2rayng' => '1.9.5',
        'v2rayN' => '6.31',
        'surge' => '2398'
    ];
    // allowed types
    const AllowedTypes = ['vmess', 'vless', 'trojan', 'hysteria', 'shadowsocks', 'hysteria2'];

    public function subscribe(Request $request)
    {
        // filter types
        $types = $request->input('types', 'all');
        $typesArr = $types === 'all' ? self::AllowedTypes : array_values(array_intersect(explode('|', str_replace(['|', '｜', ','], "|", $types)), self::AllowedTypes));
        // 新增：是否支持2022-blake3-aes-256-gcm
        $ss2022 = $request->input('ss2022');
        $supportSs2022 = $ss2022 === 'true' || $ss2022 === '1' || $ss2022 === true;
        // filter keyword
        $filterArr = mb_strlen($filter = $request->input('filter')) > 20 ? null : explode("|", str_replace(['|', '｜', ','], "|", $filter));
        $flag = strtolower($request->input('flag') ?? $request->header('User-Agent', ''));
        $ip = $request->input('ip', $request->ip());
        // get client version
        $version = preg_match('/\/v?(\d+(\.\d+){0,2})/', $flag, $matches) ? $matches[1] : null;
        $supportHy2 = $version ? collect(self::SupportedHy2ClientVersions)
                ->contains(fn($minVersion, $client) => stripos($flag, $client) !== false && $this->versionCompare($version, $minVersion)) : true;
        $user = $request->user;
        
        // Log request to Redis
        $this->logRequestToRedis($ip, $user, $request);
        
        // account not expired and is not banned.
        $userService = new UserService();
        if ($userService->isAvailable($user)) {
            // get ip location
            $ip2region = new \Ip2Region();
            $region = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ($ip2region->memorySearch($ip)['region'] ?? null) : null;
            // get available servers
            $servers = ServerService::getAvailableServers($user);
            // inbound参数处理
            $inboundIndex = (int)$request->input('inbound');
            if ($inboundIndex > 0) {
                foreach ($servers as &$server) {
                    if (isset($server['ips']) && is_array($server['ips']) && count($server['ips']) >= $inboundIndex) {
                        $server['host'] = $server['ips'][$inboundIndex - 1];
                    }
                }
                unset($server);
            }
            \Log::info('Available servers');
            // filter servers
            $serversFiltered = $this->serverFilter($servers, $typesArr, $filterArr, $region, $supportHy2, $supportSs2022);
            $this->setSubscribeInfoToServers($serversFiltered, $user, count($servers) - count($serversFiltered));
            $servers = $serversFiltered;
            $this->addPrefixToServerName($servers);
            if ($flag) {
                foreach (array_reverse(glob(app_path('Protocols') . '/*.php')) as $file) {
                    $file = 'App\\Protocols\\' . basename($file, '.php');
                    $class = new $file($user, $servers);
                    $classFlags = explode(',', $class->flag);
                    foreach ($classFlags as $classFlag) {
                        if (stripos($flag, $classFlag) !== false) {
                            return $class->handle();
                        }
                    }
                }
            }
            $class = new General($user, $servers);
            return $class->handle();
        }
    }
    
    /**
     * Log request information to Redis
     * 
     * @param string $ip
     * @param array $user
     * @param Request $request
     * @return void
     */
    private function logRequestToRedis($ip, $user, Request $request)
    {
        try {
            $timestamp = time();
            $userId = $user['id'] ?? 'unknown';
            $email = $user['email'] ?? 'unknown';
            
            // Create a Redis key for this user
            $redisKey = "user_requests:{$userId}";
            
            // Prepare request data
            $requestData = json_encode([
                'ip' => $ip,
                'user_id' => $userId,
                'email' => $email,
                'timestamp' => $timestamp,
                'datetime' => date('Y-m-d H:i:s', $timestamp),
                'user_agent' => $request->header('User-Agent', ''),
            ]);
            
            // Add to a list of requests for this user (newest first)
            Redis::lpush($redisKey, $requestData);
            
            // Trim the list to keep only the most recent 100 entries
            Redis::ltrim($redisKey, 0, 99);
            
            // Set expiration (e.g., 7 days)
            Redis::expire($redisKey, 7 * 24 * 60 * 60);
            
            // Also maintain a sorted set of users by last activity
            Redis::zadd('active_users', $timestamp, $userId);
            
            // \Log::info("Request logged to Redis for user {$userId} from IP {$ip}");
        } catch (\Exception $e) {
            \Log::error("Failed to log request to Redis: " . $e->getMessage());
        }
    }
    
    /**
     * Summary of serverFilter
     * @param mixed $typesArr
     * @param mixed $filterArr
     * @param mixed $region
     * @param mixed $supportHy2
     * @param mixed $supportSs2022 
     * @return array
     */
    private function serverFilter($servers, $typesArr, $filterArr, $region, $supportHy2, $supportSs2022)
    {
        return collect($servers)->reject(function ($server) use ($typesArr, $filterArr, $region, $supportHy2, $supportSs2022) {
            // 1. 首先检查协议类型
            if (!in_array($server['type'], $typesArr)) {
                return true;
            }

            // 2. 检查hysteria2支持
            if ($server['type'] === 'hysteria' && $server['version'] === 2) {
                if (!in_array('hysteria2', $typesArr) || !$supportHy2) {
                    return true;
                }
            }

            // 3. 处理shadowsocks节点
            if ($server['type'] === 'shadowsocks') {
                $isSs2022 = isset($server['cipher']) && $server['cipher'] === '2022-blake3-aes-256-gcm';
                // 根据ss2022参数过滤
                if ($supportSs2022 && !$isSs2022) {
                    return true;
                }
                if (!$supportSs2022 && $isSs2022) {
                    return true;
                }
            }

            // 4. 处理过滤器
            if ($filterArr) {
                $matchFilter = false;
                foreach ($filterArr as $filter) {
                    if (stripos($server['name'], $filter) !== false || 
                        in_array($filter, $server['tags'] ?? [])) {
                        $matchFilter = true;
                        break;
                    }
                }
                if (!$matchFilter) {
                    return true;
                }
            }

            // 5. 处理区域过滤
            if (strpos($region, '中国') !== false) {
                $excludes = $server['excludes'] ?? [];
                if (!empty($excludes)) {
                    foreach ($excludes as $v) {
                        $excludeList = explode("|", str_replace(["｜", ",", " ", "，"], "|", $v));
                        foreach ($excludeList as $needle) {
                            if (stripos($region, $needle) !== false) {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        })->values()->all();
    }
    /*
     * add prefix to server name
     */
    private function addPrefixToServerName(&$servers)
    {
        // 线路名称增加协议类型
        if (admin_setting('show_protocol_to_server_enable')) {
            $typePrefixes = [
                'hysteria' => [1 => '[Hy]', 2 => '[Hy2]'],
                'vless' => '[vless]',
                'shadowsocks' => '[ss]',
                'vmess' => '[vmess]',
                'trojan' => '[trojan]',
            ];
            $servers = collect($servers)->map(function ($server) use ($typePrefixes) {
                if (isset($typePrefixes[$server['type']])) {
                    $prefix = is_array($typePrefixes[$server['type']]) ? $typePrefixes[$server['type']][$server['version']] : $typePrefixes[$server['type']];
                    $server['name'] = $prefix . $server['name'];
                }
                return $server;
            })->toArray();
        }
    }

    /**
     * Summary of setSubscribeInfoToServers
     * @param mixed $servers
     * @param mixed $user
     * @param mixed $rejectServerCount
     * @return void
     */
    private function setSubscribeInfoToServers(&$servers, $user, $rejectServerCount = 0)
    {
        if (!isset($servers[0]))
            return;
        // if ($rejectServerCount > 0) {
        //     array_unshift($servers, array_merge($servers[0], [
        //         'name' => "过滤掉{$rejectServerCount}条线路",
        //     ]));
        // }
        if (!(int) admin_setting('show_info_to_server_enable', 0))
            return;
        $useTraffic = $user['u'] + $user['d'];
        $totalTraffic = $user['transfer_enable'];
        $remainingTraffic = Helper::trafficConvert($totalTraffic - $useTraffic);
        $expiredDate = $user['expired_at'] ? date('Y-m-d', $user['expired_at']) : '长期有效';
        $userService = new UserService();
        $resetDay = $userService->getResetDay($user);
        array_unshift($servers, array_merge($servers[0], [
            'name' => "套餐到期：{$expiredDate}",
        ]));
        if ($resetDay) {
            array_unshift($servers, array_merge($servers[0], [
                'name' => "距离下次重置剩余：{$resetDay} 天",
            ]));
        }
        array_unshift($servers, array_merge($servers[0], [
            'name' => "剩余流量：{$remainingTraffic}",
        ]));
    }


    /**
     * 判断版本号
     */

    function versionCompare($version1, $version2)
    {
        if (!preg_match('/^\d+(\.\d+){0,2}/', $version1) || !preg_match('/^\d+(\.\d+){0,2}/', $version2)) {
            return false;
        }
        $v1Parts = explode('.', $version1);
        $v2Parts = explode('.', $version2);

        $maxParts = max(count($v1Parts), count($v2Parts));

        for ($i = 0; $i < $maxParts; $i++) {
            $part1 = isset($v1Parts[$i]) ? (int) $v1Parts[$i] : 0;
            $part2 = isset($v2Parts[$i]) ? (int) $v2Parts[$i] : 0;

            if ($part1 < $part2) {
                return false;
            } elseif ($part1 > $part2) {
                return true;
            }
        }

        // 版本号相等
        return true;
    }
}
