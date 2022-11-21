<?php

namespace LaravelGuard\JWT\Guards;

use LaravelGuard\JWT\Helpers\JWT;
use App\Models\User;
use BadMethodCallException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;

class JWTGuard implements Guard
{
    use GuardHelpers, Macroable {
        __call as macroCall;
    }

    protected $lastAttempted;
    protected $jwt;
    protected $request;

    /**
     * Instantiate the class.
     *
     * @param JWT $jwt
     * @param UserProvider $provider
     * @param Request $request
     */
    public function __construct(JWT $jwt, UserProvider $provider, Request $request)
    {
        $this->jwt = $jwt;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null|User
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $token = $this->jwt->getToken($this->request, true);


        if (($payload = $this->jwt->decode($token))) {
            return $this->user = $this->provider->retrieveById($payload->sub);
        }

        return null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return (bool) $this->attempt($credentials, false);
    }

    /**
     * Return the currently cached user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the current request instance.
     *
     * @return \Illuminate\Http\Request
     */
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }


    /**
     * Magically call the JWT instance.
     *
     * @param  string  $method
     * @param  array  $parameters
     * @return mixed
     *
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
