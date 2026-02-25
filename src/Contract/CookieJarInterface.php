<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/cookie.
 *
 * @link     https://github.com/hyperf-ext/cookie
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/cookie/blob/master/LICENSE
 */
namespace HyperfExt\Cookie\Contract;

use Hyperf\HttpMessage\Cookie\Cookie;

interface CookieJarInterface
{
    /**
     * Create a new cookie instance.
     *
     * @param string $name
     * @param string $value
     * @param int $minutes
     * @param string|null $path
     * @param string|null $domain
     * @param bool|null $secure
     * @param bool $httpOnly
     * @param bool $raw
     * @param string|null $sameSite
     * @return Cookie
     */
    public function make(string $name, string $value, int $minutes = 0, ?string $path = null, ?string $domain = null, ?bool $secure = null, bool $httpOnly = true, bool $raw = false, ?string $sameSite = null): Cookie;

    /**
     * Create a cookie that lasts "forever" (five years).
     *
     * @param string $name
     * @param string $value
     * @param string|null $path
     * @param string|null $domain
     * @param bool|null $secure
     * @param bool $httpOnly
     * @param bool $raw
     * @param string|null $sameSite
     * @return Cookie
     */
    public function forever(string $name, string $value, ?string $path = null, ?string $domain = null, ?bool $secure = null, bool $httpOnly = true, bool $raw = false, ?string $sameSite = null): Cookie;

    /**
     * Expire the given cookie.
     *
     * @param string $name
     * @param string|null $path
     * @param string|null $domain
     * @return Cookie
     */
    public function forget(string $name, ?string $path = null, ?string $domain = null): Cookie;

    /**
     * Queue a cookie to send with the next response.
     */
    public function queue(Cookie $cookie): void;

    /**
     * Remove a cookie from the queue.
     */
    public function unqueue(string $name, ?string $path = null): void;

    /**
     * Get the cookies which have been queued for the next request.
     *
     * @return Cookie[]
     */
    public function getQueuedCookies(): array;
}
