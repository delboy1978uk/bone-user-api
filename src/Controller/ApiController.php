<?php

namespace Bone\BoneUserApi\Controller;

use Bone\BoneDoctrine\EntityManagerAwareInterface;
use Bone\BoneDoctrine\HasEntityManagerTrait;
use Bone\Controller\Controller;
use Bone\I18n\Form;
use Bone\Mail\EmailMessage;
use Bone\Mail\Service\MailService;
use Bone\OAuth2\Controller\AuthServerController;
use Bone\OAuth2\Entity\Client;
use Bone\Server\SessionAwareInterface;
use Bone\Server\Traits\HasSessionTrait;
use Bone\User\Form\PersonForm;
use DateTime;
use Defuse\Crypto\Key;
use Del\Entity\User;
use Del\Exception\EmailLinkException;
use Del\Exception\UserException;
use Del\Factory\CountryFactory;
use Del\Form\Field\Text\EmailAddress;
use Del\Service\UserService;
use Del\Value\User\State;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\Uri;
use League\OAuth2\Server\CryptKey;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ApiController extends Controller implements EntityManagerAwareInterface, SessionAwareInterface
{
    use HasEntityManagerTrait;
    use HasSessionTrait;

    private array $nativeAppSettings;
    private array $oauth2settings;
    private AuthServerController $authServerController;
    private CryptKey $privateKey;
    private Key $encryptionKey;
    private MailService $mailService;
    private UserService $userService;

    /**
     * BoneUserController constructor.
     * @param UserService $userService
     */
    public function __construct(UserService $userService, MailService $mailService, AuthServerController $authServerController, array $nativeAppSettings)
    {
        $this->userService = $userService;
        $this->mailService = $mailService;
        $this->nativeAppSettings = $nativeAppSettings;
        $this->authServerController = $authServerController;
    }

    /**
     * User profile data.
     * @OA\Get(
     *     path="/api/user/profile",
     *     @OA\Response(response="200", description="User profile data"),
     *     tags={"user"},
     *     security={
     *         {"oauth2": {"basic"}}
     *     }
     * )
     * @param ServerRequestInterface $request
     * @param array $args
     * @return ResponseInterface
     */
    public function profileAction(ServerRequestInterface $request): ResponseInterface
    {
        /** @var User $user */
        $user = $request->getAttribute('user');
        $person = $user->getPerson();
        $country = $person->getCountry();
        $user = $this->userService->toArray($user);
        $dob = $person->getDob() ? $person->getDob()->format('Y-m-d H:i:s') : null;
        $person = $this->userService->getPersonSvc()->toArray($person);
        $person['dob'] = $dob;
        $person['country'] = $country ? $country->toArray() : null;
        $user['person'] = $person;
        unset($user['password']);

        return new JsonResponse($user);
    }


    /**
     * Register a new user.
     * @OA\Post(
     *     path="/api/user/register",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"email", "password", "confirm"},
     *                 @OA\Property(
     *                     property="email",
     *                     type="string",
     *                     example="fake@email.com",
     *                     description="The new user's email"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="Email sent"),
     *     tags={"user"},
     *     security={
     *         {"oauth2": {"register"}}
     *     }
     * )
     * @param ServerRequestInterface $request
     * @param array $args
     * @return ResponseInterface
     * @throws Exception
     */
    public function registerAction(ServerRequestInterface $request): ResponseInterface
    {
        $form = new Form('register', $this->getTranslator());
        $email = new EmailAddress('email');
        $form->addField($email);
        $responseData = [];
        $formData = $request->getParsedBody();
        $form->populate($formData);

        if ($form->isValid()) {
            $data = $form->getValues();
            try {
                $user = $this->userService->registerNewUserWithoutPassword($data['email']);
                $link = $this->userService->generateEmailLink($user);
                $mail = $this->mailService;

                $env = $mail->getSiteConfig()->getEnvironment();
                $email = $user->getEmail();
                $token = $link->getToken();

                $mail = new EmailMessage();
                $mail->setTo($user->getEmail());
                $mail->setSubject($this->getTranslator()->translate('email.user.register.thankswith', 'user') . ' ' . $this->mailService->getSiteConfig()->getTitle());
                $mail->setTemplate('email.user::user_registration/api_user_registration');
                $mail->setViewData([
                    'siteUrl' => $env->getSiteURL(),
                    'logo' => $this->getSiteConfig()->getEmailLogo(),
                    'activationLink' => $this->nativeAppSettings['deepLink'] . 'user/activate?email=' . $email . '&token=' . $token,
                    'address' => $this->getSiteConfig()->getAddress(),
                ]);
                $this->mailService->sendEmail($mail);

                $responseData['success'] = 'Email sent to ' . $email;
                $status = 200;

            } catch (UserException $e) {
                $responseData['error'] = $e->getMessage();
                $responseData['code'] = $e->getCode();
                $status = $e->getCode();
            }
        } else {
            $responseData['error'] = $form->getErrorMessages();
            $responseData['code'] = 400;
            $status = 400;
        }

        return new JsonResponse($responseData, $status);
    }

    /**
     * Validates an email token.
     * @OA\Post(
     *     path="/api/user/validate-email-token",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"email", "token"},
     *                 @OA\Property(
     *                     property="email",
     *                     type="string",
     *                     example="fake@email.com",
     *                     description="The email of the user."
     *                 ), @OA\Property(
     *                     property="token",
     *                     type="string",
     *                     example="xxxxxxxxxx",
     *                     description="The security token from the email."
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="{ok: true}}"),
     *     tags={"user"}
     * )
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws \Doctrine\ORM\ORMException
     * @throws \Doctrine\ORM\OptimisticLockException
     */
    public function validateEmailToken(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody();
        $email = $body['email'];
        $token = $body['token'];

        try {
            $this->userService->findEmailLink($email, $token);

            return new JsonResponse(['ok' => true]);
        } catch (EmailLinkException $e) {
            return new JsonResponse(['error' => $e->getMessage()]);
        }
    }

    /**
     * Activate a new user.
     * @OA\Post(
     *     path="/api/user/activate",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"email", "token"},
     *                 @OA\Property(
     *                     property="email",
     *                     type="string",
     *                     example="fake@email.com",
     *                     description="The account to activate"
     *                 ), @OA\Property(
     *                     property="token",
     *                     type="string",
     *                     example="xxxxxxxxxx",
     *                     description="The security token from the email"
     *                 ), @OA\Property(
     *                     property="clientId",
     *                     type="string",
     *                     example="xxxxxxxxxx",
     *                     description="The clientId of the app"
     *                 ), @OA\Property(
     *                     property="password",
     *                     type="string",
     *                     example="xxxxxxxxxx",
     *                     description="The new users password"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="Email sent"),
     *     tags={"user"},
     *     security={
     *         {"oauth2": {"register"}}
     *     }
     * )
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws \Doctrine\ORM\ORMException
     * @throws \Doctrine\ORM\OptimisticLockException
     */
    public function activateAction(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody();
        $clientId = $body['clientId'];
        $email = $body['email'];
        $token = $body['token'];
        $password = $body['password'];
        $userService = $this->userService;
        $client = $this->getEntityManager()->getRepository(Client::class)->getClientEntity($clientId);

        if (!$client) {
            return new JsonResponse([
                'error' => 'Client not found'
            ], 404);
        }

        try {
            $link = $userService->findEmailLink($email, $token);
            $user = $link->getUser();
            $user->setState(new State(State::STATE_ACTIVATED));
            $user->setLastLogin(new DateTime());
            $userService->changePassword($user, $password);
            $userService->saveUser($user);
            $userService->deleteEmailLink($link);
            $this->getSession()->set('user', $user->getId());
            $authRequest = $this->getAuthRequest($clientId);
            $response = $this->authServerController->authorizeAction($authRequest, []);
            $redirectUri = $response->getHeaderLine('Location');
            $url = \parse_url($redirectUri);\parse_str($url['query'], $params);
            $code = $params['code'];
            $tokenRequest = $this->getTokenRequest($clientId, $code);
            $response = $this->authServerController->accessTokenAction($tokenRequest, []);

            return $response;

        } catch (EmailLinkException $e) {
            $body = ['error' => $e->getMessage()];
            $status = 400;
        } catch (Exception $e) {
            return new JsonResponse(['error' => $e->getMessage()]);
        }

        return new JsonResponse($body, $status);
    }

    private function getAuthRequest(string $clientId): ServerRequestInterface
    {
        $url = $this->getSiteConfig()->getBaseUrl() . '/oauth2/authorize';
        $query = [
            'client_id' => $clientId,
            'code_challenge' => $this->generatePkceCodeChallenge($this->nativeAppSettings['verifier']),
            'code_challenge_method' => 'S256',
            'response_type' => 'code',
            'redirect_uri' => $this->nativeAppSettings['deepLink'] . 'oauth2/callback',
            'scope' => 'basic',
            'state' => 'xxx',
        ];

        $request = new ServerRequest('POST', $url);
        $request = $request->withQueryParams($query);

        return $request;
    }

    private function getTokenRequest(string $clientId, string $code): ServerRequestInterface
    {
        $url = $this->getSiteConfig()->getBaseUrl() . '/oauth2/token';
        $body = [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code_verifier' => $this->nativeAppSettings['verifier'],
            'redirect_uri' => $this->nativeAppSettings['deepLink'] . 'oauth2/callback',
            'code' => $code
        ];

        $request = ServerRequestFactory::fromGlobals(null, [], $body);
        $request = $request->withMethod('POST');
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        return $request->withUri(new Uri($url));
    }

    private function generatePkceCodeChallenge(string $verifier)
    {
        $hash = hash('sha256', $verifier, true);

        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Resend an activation email.
     * @OA\Post(
     *     path="/api/user/resend-activation-email",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"email", "token"},
     *                 @OA\Property(
     *                     property="email",
     *                     type="string",
     *                     example="fake@email.com",
     *                     description="The account to resend the email to"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="{ok: true}"),
     *     tags={"user"},
     * )
     * @param ServerRequestInterface $request
     * @param array $args
     * @return ResponseInterface
     */
    public function resendActivationEmailAction(ServerRequestInterface $request): ResponseInterface
    {
        $email = $request->getParsedBody()['email'];
        $user = $this->userService->findUserByEmail($email);
        $translator = $this->getTranslator();

        if (!$user) {
            throw new Exception(UserException::USER_NOT_FOUND, 404);
        }

        if ($user->getState()->getValue() == State::STATE_ACTIVATED) {
            throw new Exception(UserException::USER_ACTIVATED, 400);
        }

        $link = $this->userService->generateEmailLink($user);
        $mail = $this->mailService;

        $env = $mail->getSiteConfig()->getEnvironment();
        $email = $user->getEmail();
        $token = $link->getToken();

        $mail = new EmailMessage();
        $mail->setTo($user->getEmail());
        $mail->setSubject($translator->translate('email.user.register.thankswith', 'user') . ' ' . $this->mailService->getSiteConfig()->getTitle());
        $mail->setTemplate('email.user::user_registration/api_user_registration');
        $mail->setViewData([
            'siteUrl' => $env->getSiteURL(),
            'logo' => $this->getSiteConfig()->getEmailLogo(),
            'address' => $this->getSiteConfig()->getAddress(),
            'activationLink' => $this->nativeAppSettings['deepLink'] . 'user/activate?email=' . $email . '&token=' . $token,
        ]);
        $this->mailService->sendEmail($mail);

        return new JsonResponse([
            'ok' => true
        ]);
    }

    /**
     * Update user profile data.
     * @OA\Put(
     *     path="/api/user/profile",
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"email", "password", "confirm"},
     *                 @OA\Property(
     *                     property="firstname",
     *                     type="string",
     *                     example="Captain",
     *                     description="The user's firstname"
     *                 ),@OA\Property(
     *                     property="middlename",
     *                     type="string",
     *                     example="Jack",
     *                     description="The users middlename"
     *                 ),@OA\Property(
     *                     property="lastname",
     *                     type="string",
     *                     example="Sparrow",
     *                     description="The user's surname"
     *                 ),
     *                  @OA\Property(
     *                     property="aka",
     *                     type="string",
     *                     example="outlaw pirate",
     *                     description="The user's nickname"
     *                 ),
     *                  @OA\Property(
     *                     property="dob",
     *                     type="date",
     *                     example="2014-09-18",
     *                     description="The user's date of birth"
     *                 ),
     *                  @OA\Property(
     *                     property="birthplace",
     *                     type="string",
     *                     example="Jamaica",
     *                     description="The user's birthplace"
     *                 ),
     *                  @OA\Property(
     *                     property="country",
     *                     type="string",
     *                     example="JM",
     *                     description="The user's country"
     *                 ),
     *             )
     *         )
     *     ),
     *     @OA\Response(response="200", description="Success message"),
     *     tags={"user"},
     *     security={
     *         {"oauth2": {"basic"}}
     *     }
     * )
     * @param ServerRequestInterface $request
     * @param array $args
     * @return ResponseInterface
     * @throws Exception
     */
    public function editProfileAction(ServerRequestInterface $request): ResponseInterface
    {
        $data = $request->getParsedBody();
        $form = new PersonForm('profile', $this->getTranslator());
        $form->populate($data);

        if ($form->isValid()) {
            $data = $form->getValues();
            $data['dob'] = new DateTime($data['dob']);
            $data['country'] = CountryFactory::generate($data['country']);
            $user = $request->getAttribute('user');
            $person = $user->getPerson();
            $personService = $this->userService->getPersonSvc();
            $person = $personService->populateFromArray($person, $data);
            $person = $personService->toArray($person);
            $person['country'] = $person['country']->toArray();

            return new JsonResponse($person);
        }

        return new JsonResponse($form->getErrorMessages());
    }
}
