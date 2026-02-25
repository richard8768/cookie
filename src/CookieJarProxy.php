<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/cookie.
 *
 * @link     https://github.com/hyperf-ext/cookie
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/cookie/blob/master/LICENSE
 */
namespace HyperfExt\Cookie;

use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpMessage\Cookie\Cookie;
use Hyperf\Context\Context;
use HyperfExt\Cookie\Contract\CookieJarInterface;

class CookieJarProxy extends CookieJar
{
    /**
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    public function __construct(ConfigInterface $config)
    {
        $this->config = $config;
    }

    public function hasQueued(string $key, ?string $path = null): bool
    {
        return $this->getCookieJar()->hasQueued($key, $path);
    }

    public function queued(string $key, mixed $default = null, ?string $path = null): ?Cookie
    {
        return $this->getCookieJar()->queued($key, $default, $path);
    }

    public function queue(Cookie $cookie): void
    {
        $this->getCookieJar()->queue($cookie);
    }

    public function unqueue(string $name, ?string $path = null): void
    {
        $this->getCookieJar()->unqueue($name, $path);
    }

    public function setDefaultPathAndDomain(string $path, string $domain, bool $secure = false, ?string $sameSite = null): CookieJarInterface
    {
        return $this->getCookieJar()->setDefaultPathAndDomain($path, $domain, $secure, $sameSite);
    }

    public function getQueuedCookies(): array
    {
        return $this->getCookieJar()->getQueuedCookies();
    }

    public function getPathAndDomain(?string $path = null, ?string $domain = null, ?bool $secure = null, ?string $sameSite = null): array
    {
        return $this->getCookieJar()->getPathAndDomain($path, $domain, $secure, $sameSite);
    }

    protected function getCookieJar(): CookieJarInterface
    {
        if (! Context::has(CookieJarInterface::class)) {
            $cookieJar = new CookieJar();
            $config = $this->config->get('cookie', []);
            $cookieJar->setDefaultPathAndDomain(
                $config['path'] ?? '/',
                $config['domain'] ?? '',
                false,
                $config['same_site'] ?? 'lax'
            );
            Context::set(CookieJarInterface::class, $cookieJar);
        }
        return Context::get(CookieJarInterface::class);
    }
}
