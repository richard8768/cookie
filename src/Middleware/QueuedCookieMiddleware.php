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

use Hyperf\Contract\ConfigInterface;
use HyperfExt\Cookie\Contract\CookieJarInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class QueuedCookieMiddleware implements MiddlewareInterface
{
    /**
     * @var CookieJarInterface
     */
    private CookieJarInterface $cookieJar;

    /**
     * @var ConfigInterface
     */
    private ConfigInterface $config;

    public function __construct(CookieJarInterface $cookieJar, ConfigInterface $config)
    {
        $this->cookieJar = $cookieJar;
        $this->config = $config;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $uri = $request->getUri();
        $secure = strtolower($uri->getScheme()) === 'https';
        [$path, $domain, , $sameSite] = $this->cookieJar->getPathAndDomain();
        $this->cookieJar->setDefaultPathAndDomain($path, $domain, $secure, $sameSite);

        $response = $handler->handle($request);

        foreach ($this->cookieJar->getQueuedCookies() as $cookie) {
            $response = $response->withCookie($cookie);
        }

        return $response;
    }
}
