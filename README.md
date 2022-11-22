## Laravel Guard JWT Validator

This package used for microservices to validate the JWT access token and create user if is not exists. 
It built on Laravel Guard model, so developer could use the auth config and helper to setup the packager programmer.


### Install

Require this package with composer using the following command:

```bash
composer require dweik/laravel-guard-jwt-validator
```

Then you need publish the config files by execute the following command
```bash
php artisan vendor:publish --tag=laravel-guard-jwt-config
```

Then you have set up the JWT configuration values in `config/jwt.php`, and add the follow values 
in `config/auth.php` to add new guard to laravel project

```
    'guards' => [
        .
        .
        // add under guards value
        'jwt' => [
            'driver' => 'jwt',
            'provider' => 'guard-jwt',
        ],
    ]
    
    'providers' => [
        .
        .
        // add under providers value
        'guard-jwt' => [
             'driver' => 'guard-jwt',
             'model' => \App\Models\User::class
        ],
    ]
```
___

### How to use

you can add guard to middleware or use it as default guard by changing the `defaults` value in `config/auth.php` 



### Changelog

V1.0.1
* [bugfix] return an exception `Token not valid` if token not passed

V1.0.0
* Validate the JWT token
* Create user if is not exists by using the JWT payload values
