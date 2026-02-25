<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/cookie.
 *
 * @link     https://github.com/hyperf-ext/cookie
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/cookie/blob/master/LICENSE
 */
namespace HyperfExt\Cookie\Middleware;

use Hyperf\HttpMessage\Cookie\Cookie;
use Hyperf\Collection\Arr;
use HyperfExt\Cookie\CookieValuePrefix;
use HyperfExt\Encryption\Contract\AsymmetricDriverInterface;
use HyperfExt\Encryption\Contract\EncryptionInterface;
use HyperfExt\Encryption\Contract\SymmetricDriverInterface;
use HyperfExt\Encryption\Exception\DecryptException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class EncryptCookieMiddleware
{
    /**
     * The encrypter instance.
     *
     * @var AsymmetricDriverInterface|SymmetricDriverInterface
     */
    protected AsymmetricDriverInterface|SymmetricDriverInterface $encrypter;

    /**
     * The names of the cookies that should not be encrypted.
     *
     * @var array
     */
    protected array $except = [];

    /**
     * Indicates if cookies should be serialized.
     *
     * @var bool
     */
    protected static bool $serialize = false;

    /**
     * Create a new CookieGuard instance.
     */
    public function __construct(EncryptionInterface $encrypter)
    {
        $this->encrypter = $encrypter->getDriver();
    }

    /**
     * Disable encryption for the given cookie name(s).
     *
     * @param array|string $name
     */
    public function disableFor(array|string $name): void
    {
        $this->except = array_merge($this->except, (array) $name);
    }

    /**
     * Handle an incoming request.
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->encrypt($handler->handle($this->decrypt($request)));
    }

    /**
     * Determine whether encryption has been disabled for the given cookie.
     * @param string $name
     * @return bool
     */
    public function isDisabled(string $name): bool
    {
        return in_array($name, $this->except);
    }

    /**
     * Determine if the cookie contents should be serialized.
     */
    public static function serialized(string $name): bool
    {
        return static::$serialize;
    }

    /**
     * Decrypt the cookies on the request.
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    protected function decrypt(ServerRequestInterface $request): ServerRequestInterface
    {
        $cookies = [];

        foreach ($request->getCookieParams() as $key => $cookie) {
            if ($this->isDisabled($key)) {
                continue;
            }

            try {
                $value = $this->decryptCookie($key, $cookie);

                $hasValidPrefix = strpos($value, CookieValuePrefix::create(
                    $key,
                    $this->encrypter instanceof SymmetricDriverInterface
                        ? $this->encrypter->getKey()
                        : $this->encrypter->getPublicKey()
                )) === 0;

                $cookies[$key] = $hasValidPrefix ? CookieValuePrefix::remove($value) : null;
            } catch (DecryptException $e) {
                $cookies[$key] = null;
            }
        }

        return $request->withCookieParams($cookies);
    }

    /**
     * Decrypt the given cookie and return the value.
     *
     * @param string $name
     * @param array|string $cookie
     *
     * @return array|string
     */
    protected function decryptCookie(string $name, $cookie): array|string
    {
        return is_array($cookie)
            ? $this->decryptArray($cookie)
            : $this->encrypter->decrypt($cookie, static::serialized($name));
    }

    /**
     * Decrypt an array based cookie.
     *
     * @param array $cookie
     * @return array
     */
    protected function decryptArray(array $cookie): array
    {
        $decrypted = [];

        foreach ($cookie as $key => $value) {
            if (is_string($value)) {
                $decrypted[$key] = $this->encrypter->decrypt($value, static::serialized($key));
            }
        }

        return $decrypted;
    }

    /**
     * Encrypt the cookies on an outgoing response.
     *
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    protected function encrypt(ResponseInterface $response): ResponseInterface
    {
        $cookies = Arr::flatten($response->getCookies());
        foreach ($cookies as $cookie) {
            if ($this->isDisabled($cookie->getName())) {
                continue;
            }

            $response = $response->withCookie($this->duplicate(
                $cookie,
                $this->encrypter->encrypt(
                    CookieValuePrefix::create(
                        $cookie->getName(),
                        $this->encrypter instanceof SymmetricDriverInterface
                            ? $this->encrypter->getKey()
                            : $this->encrypter->getPublicKey()
                    ) . $cookie->getValue(),
                    static::serialized($cookie->getName())
                )
            ));
        }

        return $response;
    }

    /**
     * Duplicate a cookie with a new value.
     *
     * @param Cookie $cookie
     * @param string $value
     * @return Cookie
     */
    protected function duplicate(Cookie $cookie, string $value): Cookie
    {
        return new Cookie(
            $cookie->getName(),
            $value,
            $cookie->getExpiresTime(),
            $cookie->getPath(),
            $cookie->getDomain(),
            $cookie->isSecure(),
            $cookie->isHttpOnly(),
            $cookie->isRaw(),
            $cookie->getSameSite()
        );
    }
}
