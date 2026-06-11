# Hyperf Cookie 组件

该组件移植自 Laravel（[illuminate/cookie](https://github.com/illuminate/cookie )），功能与 Laravel 保持一致。

> 注意，该组件与 Hyperf 官方组件差异很大，使用时切勿混淆。

## 安装

```shell script
composer require richard8768/cookie
```

## 发布配置

```shell script
php bin/hyperf.php vendor:publish richard8768/cookie
```

> 配置文件位于 `config/autoload/cookie.php`。

## 设置

在配置文件 `config/autoload/middlewares.php` 中添加全局中间件 `HyperfExt\Cookie\Middleware\QueuedCookieMiddleware`。

如需对 Cookie 加密，额外添加全局中间件 `HyperfExt\Cookie\Middleware\EncryptCookieMiddleware`。

> 注意，使用 Cookie 加密中间件需要依赖 [`richard8768/encryption`](https://github.com/richard8768/encryption) 组件。
> 并且需求将该中间件放置在其他需要处理 Cookie 的中间件之前，以保证将请求中的加密 Cookie 解密。

## 使用

在任何需要设置 Cookie 的地方注入 `HyperfExt\Cookie\Contract\CookieJarInterface`，该接口绑定的是 `HyperfExt\Cookie\CookieJar` 的代理类实例对象。

该对象存储在当前请求的协程上下文中，在当前协程周期内访问到的都是同一个对象。

