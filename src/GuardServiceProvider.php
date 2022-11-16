<?php

namespace LaravelGuard\JWT;

use LaravelGuard\JWT\Exceptions\AuthenticationException;
use LaravelGuard\JWT\Exceptions\ConfigurationException;
use LaravelGuard\JWT\Guards\JWTGuard;
use LaravelGuard\JWT\Helpers\JWT;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use LaravelGuard\JWT\UserProviders\ValidUserProvider;

class GuardServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {

        $auth = $this->app['auth'];

        $auth->provider('guard-jwt', function ($app, array $config) {

            $request = $app['request'];

            $accessToken = JWT::getToken($request);

            $jwt = new JWT(config('jwt.algo'), config('jwt.keys.public'));

            try {
                $payload = $jwt->decode($accessToken);
            }
            catch (Exception $e) {
                $payload = false;
            }


            if (!isset($payload->sub)) {
                return new ValidUserProvider(null);
            }

            if(!(isset($config['model']) && class_exists($config['model']))){
                throw new ConfigurationException('Model is not set on auth provider.');
            }

            $user = $config['model']::find($payload->id);

            if (!$user) {

                $fillable = (new $config['model'])->getFillable();

                $create = [];

                foreach ($fillable as $key){
                    if(isset($payload->$key)) {
                        $create[$key] = $payload->$key;
                    }
                }

                throw_if(count($create)==0, new AuthenticationException('Token not valid'));
                $config['model']::create($create);
            }

            return new ValidUserProvider($user);
        });

        $auth->extend('jwt', function ($app, $name, array $config) {
            $a = $app['auth']->createUserProvider($config['provider']);
            $guard = new JWTGuard(
                new JWT(config('jwt.algo'), config('jwt.keys.public')),
                $a,
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if (env('APP_ENV') == 'production') {
            URL::forceScheme('https');
            $this->app['request']->server->set('HTTPS', 'on');
        }

        $this->publishes([
            __DIR__.'/../config/jwt.php' => config_path('jwt.php')
        ], 'laravel-guard-jwt-config');
    }
}
