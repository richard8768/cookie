<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/cookie.
 *
 * @link     https://github.com/hyperf-ext/cookie
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/cookie/blob/master/LICENSE
 */
return [
    'path' => env('COOKIE_PATH', '/'),
    'domain' => env('COOKIE_DOMAIN', ''),
    'same_site' => env('COOKIE_SAME_SITE', 'lax'),
];
