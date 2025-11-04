<?php

declare(strict_types=1);

namespace Bone\BoneUserApi;

use Barnacle\Container;
use Barnacle\RegistrationInterface;
use Bone\Contracts\Container\ApiDocProviderInterface;
use Bone\Contracts\Container\DependentPackagesProviderInterface;
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
use Bone\User\Http\Controller\Api\PersonApiController;
use Bone\User\Http\Controller\Api\UserApiController;
use Del\Service\UserService;
use Laminas\Diactoros\ResponseFactory;
use League\Route\RouteGroup;
use League\Route\Strategy\JsonStrategy;

class BoneUserApiPackage implements RegistrationInterface, RouterConfigInterface, ApiDocProviderInterface, DependentPackagesProviderInterface
{
    private bool $restApi = false;

    public function addToContainer(Container $c): void
    {
        if ($c->has('bone-user')) {
            $config = $c->get('bone-user');
            $this->restApi = $config['api'] ?? false;
        }

        $c[ApiController::class] = $c->factory(function (Container $c) {
            /** @var UserService $userService */
            $userService = $c->get(UserService::class);
            $mailService = $c->get(MailService::class);
            $appSettings = $c->get('bone-native');
            $authController = $c->get(AuthServerController::class);

            return Init::controller(new ApiController($userService, $mailService, $authController, $appSettings), $c);
        });
    }

    public function addRoutes(Container $c, Router $router)
    {
        $factory = new ResponseFactory();
        $strategy = new JsonStrategy($factory);
        $strategy->setContainer($c);
        $tokenAuth = $c->get(ResourceServerMiddleware::class);
        $basicScopeCheck = new ScopeCheck(['basic']);

        $router->group('/api', function (RouteGroup $route) use ($c, $tokenAuth, $basicScopeCheck) {
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

        if ($this->restApi === true) {
            $router->apiResource('people', PersonApiController::class, $c);
            $router->apiResource('users', UserApiController::class, $c);
        }

        return $router;
    }

    public function provideModels(): array
    {
        return [
            '../../vendor/delboy1978uk/bone-user-api/data/models/person.tsp',
            '../../vendor/delboy1978uk/bone-user-api/data/models/user.tsp',
        ];
    }

    public function providePayloads(): array
    {
        return [
            '../../vendor/delboy1978uk/bone-user-api/data/payloads/email.tsp',
            '../../vendor/delboy1978uk/bone-user-api/data/payloads/activate.tsp',
        ];
    }

    public function provideResponses(): array
    {
        return [
            '../../vendor/delboy1978uk/bone-user-api/data/responses/token_response.tsp',
        ];
    }

    public function provideRoutes(): array
    {
        return $this->restApi ? [
            '../vendor/delboy1978uk/bone-user-api/data/routes/person.tsp',
            '../vendor/delboy1978uk/bone-user-api/data/routes/user_rest.tsp',
            '../vendor/delboy1978uk/bone-user-api/data/routes/user.tsp',
        ] : [
            '../vendor/delboy1978uk/bone-user-api/data/routes/user.tsp',
        ];
    }

    public function getRequiredPackages(): array
    {
        return [
            'Bone\Mail\MailPackage',
            'Bone\BoneDoctrine\BoneDoctrinePackage',
            'Bone\Paseto\PasetoPackage',
            'Del\Person\PersonPackage',
            'Del\UserPackage',
            'Del\Passport\PassportPackage',
            'Bone\Passport\PassportPackage',
            'Bone\User\BoneUserPackage',
            'Bone\OAuth2\BoneOAuth2Package',
            'Bone\OpenApi\OpenApiPackage',
            'Del\Passport\PassportPackage',
            'Bone\Passport\PassportPackage',
            self::class,
        ];
    }
}
