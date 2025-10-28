<?php

namespace Bone\BoneUserApi\Controller;

use Bone\BoneDoctrine\EntityManagerAwareInterface;
use Bone\BoneDoctrine\Traits\HasEntityManagerTrait;
use Bone\Controller\Controller;
use Bone\Http\Response\Json\CreatedResponse;
use Bone\Http\Response\Json\Error\BadRequestResponse;
use Bone\Http\Response\Json\Error\ErrorResponse;
use Bone\Http\Response\Json\Error\NotFoundResponse;
use Bone\Http\Response\Json\Error\ServerErrorResponse;
use Bone\Http\Response\Json\Error\ValidationErrorResponse;
use Bone\Http\Response\Json\OkResponse;
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
use Del\Form\Field\FileUpload;
use Del\Form\Field\Text\EmailAddress;
use Del\Image;
use Del\Service\UserService;
use Del\Value\User\State;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\Stream;
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
    private string $baseUrl;
    private string $uploadsDirectory;
    private string $tempDirectory;
    private string $imgDirectory;

    public function __construct(UserService $userService, MailService $mailService, AuthServerController $authServerController, array $nativeAppSettings)
    {
        $this->userService = $userService;
        $this->mailService = $mailService;
        $this->nativeAppSettings = $nativeAppSettings;
        $this->authServerController = $authServerController;
        $this->baseUrl = $authServerController->getSiteConfig()->getBaseUrl();
        $this->uploadsDirectory = $authServerController->getSiteConfig()->getAttribute('uploads_dir');
        $this->tempDirectory = $authServerController->getSiteConfig()->getAttribute('temp_dir');
        $this->imgDirectory = $authServerController->getSiteConfig()->getAttribute('image_dir');
    }

    public function profileAction(ServerRequestInterface $request): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $person = $user->getPerson();
        $country = $person->getCountry();
        $user = $this->userService->toArray($user);
        $dob = $person->getDob() ? $person->getDob()->format('Y-m-d') : null;
        $person = $this->userService->getPersonService()->toArray($person);
        $person['dob'] = $dob;
        $person['country'] = $country ? $country->toArray() : null;
        $person['image'] = $person['image'] ? $this->baseUrl . '/api/user/image' : null;
        $person['backgroundImage'] = $person['backgroundImage'] ? $this->baseUrl . '/api/user/background-image' : null;
        $user['person'] = $person;
        unset($user['password']);

        return new JsonResponse($user);
    }

    public function imageAction(ServerRequestInterface $request): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $file = $user->getPerson()->getImage();

        return $this->serveImage($file);
    }

    private function serveImage(string $file): ResponseInterface
    {
        $path = $this->getFilePath($file);

        if (\file_exists($path)) {
            $mimeType = $this->getMimeType($path);
            $contents = \file_get_contents($path);
            $stream = new Stream('php://memory', 'r+');
            $stream->write($contents);
            $response = new Response();
            $response = $response->withBody($stream);
            $response = $response->withHeader('Content-Type', $mimeType);

            return $response;
        }

        return new JsonResponse(['error' => 'not found'],  404);
    }

    public function backgroundImage(ServerRequestInterface $request): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $file = $user->getPerson()->getBackgroundImage();

        return $this->serveImage($file);
    }

    public function uploadImage(ServerRequestInterface $request): ResponseInterface
    {
        $data = $request->getParsedBody();
        $form = new \Del\Form\Form('upload');
        $file = new FileUpload('avatar');
        $file->setUploadDirectory($this->tempDirectory);
        $file->setRequired(true);
        $form->addField($file);
        $form->populate($data);

        if ($form->isValid()) {

            try {
                $data = $form->getValues();
                $file = $data['avatar'];
                $sourceFileName = $this->tempDirectory . $file;
                $newFileName = $this->imgDirectory . $this->getFilename($file);
                $destinationFileName = $this->uploadsDirectory . $newFileName;
                $image = new Image($sourceFileName);

                if ($image->getHeight() > $image->getWidth()) { //portrait

                    $image->resizeToWidth(100);
                    $image->crop(100, 100);

                } elseif ($image->getHeight() < $image->getWidth()) { //landscape

                    $image->resizeToHeight(100);
                    $image->crop(100, 100);

                } else { //square

                    $image->resize(100, 100);

                }
                $image->save($destinationFileName, 0775);
                unlink($sourceFileName);

                /** @var User $user */
                $user = $request->getAttribute('user');
                $person = $user->getPerson();
                $person->setImage($newFileName);
                $this->userService->getPersonService()->savePerson($person);

                return new JsonResponse([
                    'result' => 'success',
                    'message' => 'Avatar now set to ' . $person->getImage(),
                    'avatar' => $person->getImage(),
                ]);
            } catch (Exception $e) {
                return new JsonResponse([
                    'result' => 'danger',
                    'message' => $e->getMessage(),
                ], 200);
            }
        }

        return new JsonResponse([
            'result' => 'danger',
            'message' => 'There was a problem with your upload.',
        ], 400);
    }

    public function uploadBackgroundImage(ServerRequestInterface $request): ResponseInterface
    {
        $data = $request->getParsedBody();
        $form = new \Del\Form\Form('upload');
        $file = new FileUpload('background');
        $file->setUploadDirectory($this->tempDirectory);
        $file->setRequired(true);
        $form->addField($file);
        $form->populate($data);

        if ($form->isValid()) {

            try {
                $data = $form->getValues();
                $file = $data['background'];
                $sourceFileName = $this->tempDirectory . $file;
                $newFileName = $this->imgDirectory . $this->getFilename($file);
                $destinationFileName = $this->uploadsDirectory . $newFileName;
                $image = new Image($sourceFileName);

                if ($image->getHeight() > $image->getWidth()) { //portrait
                    $image->resizeToWidth(1024);
                } elseif ($image->getHeight() < $image->getWidth()) { //landscape
                    $image->resizeToHeight(768);
                } else { //square
                    $image->resizeToWidth(1024);
                }

                $image->crop(1024, 768);
                $image->save($destinationFileName, 0775);
                unlink($sourceFileName);

                /** @var User $user */
                $user = $request->getAttribute('user');
                $person = $user->getPerson();
                $person->setBackgroundImage($newFileName);
                $this->userService->getPersonService()->savePerson($person);

                return new JsonResponse([
                    'result' => 'success',
                    'message' => 'Profile background successfully uploaded ',
                    'backgroundImage' => $person->getBackgroundImage(),
                ]);
            } catch (Exception $e) {
                return new JsonResponse([
                    'result' => 'danger',
                    'message' => $e->getMessage(),
                ], 200);
            }
        }

        return new JsonResponse([
            'result' => 'danger',
            'message' => 'There was a problem with your upload.',
        ], 400);
    }

    private function getFilename(string $fileNameAsUploaded)
    {
        $filenameParts = \explode('.', $fileNameAsUploaded);
        $encoded = [];

        foreach ($filenameParts as $filenamePart) {
            $encoded[] = \urlencode($filenamePart);
        }


        $unique = \dechex(time());
        $ext = \array_pop($encoded);
        $encoded[] = $unique;
        $filenameOnDisk = \implode('_', $encoded);
        $filenameOnDisk .= '.' . $ext;

        return $filenameOnDisk;
    }

    private function getMimeType(string $path): string
    {
        $finfo = \finfo_open(FILEINFO_MIME); // return mime type
        $mimeType = \finfo_file($finfo, $path);
        \finfo_close($finfo);

        return $mimeType;
    }

    private function getFilePath(string $path): string
    {
        $path = $this->uploadsDirectory . $path;

        return $path;
    }

    public function registerAction(ServerRequestInterface $request): ResponseInterface
    {
        $form = new Form('register', $this->getTranslator());
        $email = new EmailAddress('email');
        $email->setRequired(true);
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
                $response = new CreatedResponse('Email sent to ' . $email);

            } catch (UserException $e) {
                $response = new ErrorResponse($e->getMessage(), $e->getCode());
            }
        } else {
            $response = new ValidationErrorResponse($form->getErrorMessages());
        }

        return $response;
    }

    public function validateEmailToken(ServerRequestInterface $request): ResponseInterface
    {
        $body = $request->getParsedBody();
        $email = $body['email'];
        $token = $body['token'];

        try {
            $this->userService->findEmailLink($email, $token);

            return new OkResponse(['ok' => true]);
        } catch (EmailLinkException $e) {
            return new JsonResponse(['status_code' => $e->getCode(), 'reason_phrase' => $e->getMessage()], $e->getCode());
        }
    }

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
            return new NotFoundResponse('Client not found');
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
            $url = \parse_url($redirectUri);
            $query = $url['query'];
            \parse_str($query, $params);
            $code = $params['code'];
            $tokenRequest = $this->getTokenRequest($clientId, $code);
            $response = $this->authServerController->accessTokenAction($tokenRequest, []);

            return $response;

        } catch (EmailLinkException $e) {
            return new BadRequestResponse($e->getMessage());
        } catch (Exception $e) {
            return new ServerErrorResponse($e->getMessage());
        }
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
        $request = $request->withHeader('X_BONE_USER_ACTIVATE', '1');

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

    public function resendActivationEmailAction(ServerRequestInterface $request): ResponseInterface
    {
        $email = $request->getParsedBody()['email'];
        $user = $this->userService->findUserByEmail($email);
        $translator = $this->getTranslator();

        if (!$user) {
            return new NotFoundResponse(UserException::USER_NOT_FOUND);
        }

        if ($user->getState()->getValue() == State::STATE_ACTIVATED) {
            return new BadRequestResponse(UserException::USER_ACTIVATED);
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

        return new CreatedResponse([
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
            $data['image'] = $person->getImage();
            $personService = $this->userService->getPersonService();
            $person = $personService->populateFromArray($person, $data);
            $this->userService->getPersonService()->savePerson($person);
            $person = $personService->toArray($person);
            $person['country'] = $person['country']->toArray();
            $person['dob'] = $person['dob']->format('Y-m-d');

            return new JsonResponse($person);
        }

        return new JsonResponse($form->getErrorMessages());
    }
}
