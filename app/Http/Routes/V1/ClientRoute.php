<?php
namespace App\Http\Routes\V1;

use Illuminate\Contracts\Routing\Registrar;

class ClientRoute
{
    public function map(Registrar $router)
    {
        $router->group([
            'prefix' => 'client',
            'middleware' => 'client'
        ], function ($router) {
            // Client
            $router->get('/subscribe', 'V1\\Client\\ClientController@subscribe')->name('client.subscribe');
            // App
            $router->get('/app/getConfig', 'V1\\Client\\AppController@getConfig');
            $router->get('/app/getVersion', 'V1\\Client\\AppController@getVersion');
            // Subscription Logs
            $router->get('/subscription/recent-requests', 'V1\\Client\\SubscriptionLogController@getRecentRequests');
            $router->get('/subscription/active-users', 'V1\\Client\\SubscriptionLogController@getActiveUsers');
        });
    }
}
