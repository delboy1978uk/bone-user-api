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
        $tokenAuth = $c->get(ResourceServerMiddleware::class);
        $basicScopeCheck = new ScopeCheck(['basic']);

        $router->group('/api', function (RouteGroup $route) use ($c, $tokenAuth, $basicScopeCheck) {
            $route->map('GET', '/user', [ApiController::class, 'indexAction']);
            $route->map('POST', '/user/register', [ApiController::class, 'registerAction'])->middleware(new JsonParse());
            $route->map('POST', '/user/resend-activation-email', [ApiController::class, 'resendActivationEmailAction'])->middleware(new JsonParse());
            $route->map('POST', '/user/validate-email-token', [ApiController::class, 'validateEmailToken'])->middleware(new JsonParse());
            $route->map('POST', '/user/activate', [ApiController::class, 'activateAction'])->middleware(new JsonParse());
            $route->map('GET', '/user/profile', [ApiController::class, 'profileAction'])
                ->middlewares([$tokenAuth, $basicScopeCheck, new HalEntity()]);
            $route->map('PUT', '/user/profile', [ApiController::class, 'editProfileAction'])
                ->middlewares([$tokenAuth, new ScopeCheck(['basic']), new JsonParse()]);
            $route->map('GET', '/user/image', [ApiController::class, 'imageAction'])
                ->middlewares([$tokenAuth]);
            $route->map('POST', '/user/image', [ApiController::class, 'uploadImage'])
                ->middlewares([$tokenAuth]);
            $route->map('GET', '/user/background-image', [ApiController::class, 'backgroundImage'])
                ->middlewares([$tokenAuth]);
            $route->map('POST', '/user/background-image', [ApiController::class, 'uploadBackgroundImage'])
                ->middlewares([$tokenAuth]);
        })
            ->setStrategy($strategy);

        return $router;
    }


}
