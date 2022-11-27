<?php

declare(strict_types=1);

namespace Bone\BoneUserApi;

use Barnacle\Container;
use Barnacle\RegistrationInterface;
use Bone\Controller\Init;
use Bone\Http\Middleware\HalEntity;
use Bone\Http\Middleware\JsonParse;
use Bone\Mail\Service\MailService;
use Bone\OAuth2\Controller\AuthServerController;
use Bone\OAuth2\Http\Middleware\ResourceServerMiddleware;
use Bone\OAuth2\Http\Middleware\ScopeCheck;
use Bone\Router\Router;
use Bone\Router\RouterConfigInterface;
use Bone\BoneUserApi\Controller\ApiController;
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
            $appSettings = $c->get('bone-native');
            $authController = $c->get(AuthServerController::class);

            return Init::controller(new ApiController($userService, $mailService, $authController, $appSettings), $c);
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
            $route->map('POST', '/user/register', [ApiController::class, 'registerAction'])->middleware(new JsonParse());
            $route->map('POST', '/user/resend-activation-email', [ApiController::class, 'resendActivationEmailAction'])->middleware(new JsonParse());
            $route->map('POST', '/user/validate-email-token', [ApiController::class, 'validateEmailToken'])->middleware(new JsonParse());
            $route->map('POST', '/user/activate', [ApiController::class, 'activateAction'])->middleware(new JsonParse());
            $route->map('GET', '/user/profile', [ApiController::class, 'profileAction'])
                ->middlewares([$c->get(ResourceServerMiddleware::class), new ScopeCheck(['basic']), new HalEntity()]);
            $route->map('PUT', '/user/profile', [ApiController::class, 'editProfileAction'])
                ->middlewares([$c->get(ResourceServerMiddleware::class), new ScopeCheck(['basic']), new JsonParse()]);
        })
            ->setStrategy($strategy);

        return $router;
    }


}
