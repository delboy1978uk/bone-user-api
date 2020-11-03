<?php

declare(strict_types=1);

namespace Bone\BoneUserApi;

use Barnacle\Container;
use Barnacle\RegistrationInterface;
use Bone\Controller\Init;
use Bone\Http\Middleware\HalEntity;
use Bone\Http\Middleware\JsonParse;
use Bone\Mail\Service\MailService;
use Bone\Router\Router;
use Bone\Router\RouterConfigInterface;
use Bone\User\Controller\ApiController;
use Bone\User\Http\Middleware\SessionAuth;
use Del\Service\UserService;
use Laminas\Diactoros\ResponseFactory;
use League\Route\RouteGroup;
use League\Route\Strategy\JsonStrategy;

class BoneUserApiPackage implements RegistrationInterface, RouterConfigInterface
{
    /**
     * @param Container $c
     */
    public function addToContainer(Container $c)
    {


        $c[ApiController::class] = $c->factory(function (Container $c) {
            /** @var UserService $userService */
            $userService = $c->get(UserService::class);
            $mailService = $c->get(MailService::class);

            return Init::controller(new ApiController($userService, $mailService), $c);
        });
    }

    /**
     * @param Container $c
     * @param Router $router
     */
    public function addRoutes(Container $c, Router $router)
    {
        $factory = new ResponseFactory();
        $strategy = new JsonStrategy($factory);
        $strategy->setContainer($c);

        $router->group('/api', function (RouteGroup $route) use ($c) {
            $route->map('GET', '/user', [ApiController::class, 'indexAction']);
            $route->map('POST', '/user/register', [ApiController::class, 'registerAction'])->middlewares([new JsonParse(), $c->get(ResourceServerMiddleware::class)]);
            $route->map('POST', '/user/choose-avatar', [ApiController::class, 'chooseAvatarAction'])->middleware($c->get(SessionAuth::class));
            $route->map('POST', '/user/upload-avatar', [ApiController::class, 'uploadAvatarAction'])->middleware($c->get(SessionAuth::class));
            $route->map('GET', '/user/profile', [ApiController::class, 'profileAction'])
                ->middlewares([$c->get(ResourceServerMiddleware::class), new ScopeCheck(['basic']), new HalEntity()]);
            $route->map('PUT', '/user/profile', [ApiController::class, 'editProfileAction'])
                ->middlewares([$c->get(ResourceServerMiddleware::class), new ScopeCheck(['basic']), new JsonParse()]);
        })
            ->setStrategy($strategy);

        return $router;
    }


}
