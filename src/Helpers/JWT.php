<?php

namespace LaravelGuard\JWT\Helpers;

use LaravelGuard\JWT\Exceptions\AuthenticationException;
use Illuminate\Http\Request;
use UnexpectedValueException;
use DomainException;

/**
 * @param string $jwt The JWT
 * @param string|null $key The secret key
 * @param bool $verify Don't skip verification process
 *
 * @return object The JWT's payload as a PHP object
 */
class JWT
{
    private $algo;
    private $secret;

    public function __construct($algo, $secret)
    {
        $this->algo = $algo;
        $this->secret = $secret;
    }

    public static function getToken(Request $request, $exception = false)
    {
        $token = $request->header('Authorization', ' ') . ' ';
        $token = explode(' ', $token, 2);

        if (count($token) != 2) {
            if ($exception) {
                throw new AuthenticationException('Token not valid');
            }
            return null;
        }

        list($flag, $token) = $token;

        $flag = trim($flag);
        $token = trim($token);

        if (strtolower($flag) != 'bearer') {
            if ($exception) {
                throw new AuthenticationException('Token not valid');
            }
            return null;
        }

        return $token;
    }

    public function decode($jwt, $verify = true)
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $payloadb64, $cryptob64) = $tks;
        if (null === ($header = $this->jsonDecode($this->urlsafeB64Decode($headb64)))
        ) {
            throw new UnexpectedValueException('Invalid segment encoding');
        }
        if (null === $payload = $this->jsonDecode($this->urlsafeB64Decode($payloadb64))
        ) {
            throw new UnexpectedValueException('Invalid segment encoding');
        }

        if ($verify) {
            if (empty($header->alg)) {
                throw new DomainException('Empty algorithm');
            }

            if (!isset($payload->iat)) {
                throw new UnexpectedValueException('[iat] value is missing');
            }

            if (!isset($payload->exp)) {
                throw new UnexpectedValueException('[exp] value is missing');
            }

            if (empty($payload->iat) || time() < $payload->iat) {
                throw new AuthenticationException('Issued At (iat) timestamp cannot be in the future');
            }

            if (empty($payload->exp) || time() > $payload->exp) {
                throw new AuthenticationException('Token has expired');
            }

            if (!$this->sign("$headb64.$payloadb64", $cryptob64)) {
                throw new UnexpectedValueException('Signature verification failed');
            }
        }
        return $payload;
    }

    private function sign($msg, $data)
    {
        $methods = array(
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
            'RSA' => OPENSSL_ALGO_SHA1,
            'RSA224' => OPENSSL_ALGO_SHA224,
            'RSA256' => OPENSSL_ALGO_SHA256,
            'RSA384' => OPENSSL_ALGO_SHA384,
            'RSA512' => OPENSSL_ALGO_SHA512,
        );

        $method = $this->algo;
        $key = $this->secret;


        if (empty($methods[$method])) {
            throw new DomainException('Algorithm not supported');
        }

        $data = $this->urlsafeB64Decode($data);

        if (in_array($method, ['RSA', 'RSA224', 'RSA256', 'RSA384', 'RSA512'])) {
            return $this->rsaAlog($msg, $key, $data);
        }

        return $data == hash_hmac($methods[$method], $msg, $key, true);
    }

    private function rsaAlog($msg, $key, $data)
    {
        $keyPrivatePassword = null;
        $keyPublicPath = $key;

        if (strpos($key, '@') !== false) {
            $fp = fopen(base_path(substr($keyPublicPath, 1)), "r");
            $chavePublicaString = fread($fp, 8192);
            fclose($fp);
        }
        else {
            $chavePublicaString = $key;
        }

        $resPublicKey = openssl_pkey_get_public($chavePublicaString);

        $result = openssl_verify($msg, $data, $resPublicKey, OPENSSL_ALGO_SHA256);

        openssl_free_key($resPublicKey);

        return $result;
    }

    /**
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     */
    private function jsonDecode($input)
    {
        $obj = json_decode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            $this->handleJsonError($errno);
        }
        else if ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * @param string $input A base64 encoded string
     *
     * @return string A decoded string
     */
    private function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new DomainException(isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }
}
