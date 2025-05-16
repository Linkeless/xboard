<?php
namespace App\Logging;

use Illuminate\Support\Facades\Log;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use App\Models\Log as LogModel;
use Monolog\LogRecord;

class MysqlLoggerHandler extends AbstractProcessingHandler
{
    public function __construct($level = Logger::DEBUG, bool $bubble = true)
    {
        parent::__construct($level, $bubble);
    }

    protected function write(LogRecord $record): void
    {
        $record = $record->toArray();
        try{
            if(isset($record['context']['exception']) && is_object($record['context']['exception'])){
                $record['context']['exception'] = (array)$record['context']['exception'];
            }
            $record['request_data'] = request()->all() ??[];
            $log = [
                'title' => $record['message'],
                'level' => $record['level_name'],
                'host' => $record['request_host'] ?? request()->getSchemeAndHttpHost(),
                'uri' => $record['request_uri'] ?? request()->getRequestUri(),
                'method' => $record['request_method'] ?? request()->getMethod(),
                'ip' => $this->getOriginalIp(),
                'data' => json_encode($record['request_data']) ,
                'context' => isset($record['context']) ? json_encode($record['context']) : '',
                'created_at' => $record['datetime']->getTimestamp(),
                'updated_at' => $record['datetime']->getTimestamp(),
            ];
            
            LogModel::insert(
                $log
            );
        }catch (\Exception $e){
            // Log::channel('daily')->error($e->getMessage().$e->getFile().$e->getTraceAsString());
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
