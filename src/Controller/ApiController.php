<?php

namespace Bone\BoneUserApi\Controller;

use Bone\Controller\Controller;
use Bone\Mail\EmailMessage;
use Bone\Mail\Service\MailService;
use Bone\User\Form\PersonForm;
use Bone\User\Form\RegistrationForm;
use DateTime;
use Del\Entity\User;
use Del\Exception\UserException;
use Del\Factory\CountryFactory;
use Del\Service\UserService;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ApiController extends Controller
{
    private UserService $userService;
    private MailService $mailService;
    private array $nativeAppSettings;

    /**
     * BoneUserController constructor.
     * @param UserService $userService
     */
    public function __construct(UserService $userService, MailService $mailService, array $nativeAppSettings)
    {
        $this->userService = $userService;
        $this->mailService = $mailService;
        $this->nativeAppSettings = $nativeAppSettings;
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
    public function profileAction(ServerRequestInterface $request, array $args): ResponseInterface
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
     *                 ),@OA\Property(
     *                     property="password",
     *                     type="string",
     *                     example="xxxxxxxxxx",
     *                     description="The users chosen password"
     *                 ),@OA\Property(
     *                     property="confirm",
     *                     type="string",
     *                     example="xxxxxxxxxx",
     *                     description="Password confirmation"
     *                 ),
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
     * @throws \Exception
     * @return ResponseInterface
     */
    public function registerAction(ServerRequestInterface $request, array $args): ResponseInterface
    {
        $form = new RegistrationForm('register', $this->getTranslator());
        $responseData = [];

        $formData = $request->getParsedBody();
        $form->populate($formData);

        if ($form->isValid()) {
            $data = $form->getValues();
            try {
                $user = $this->userService->registerUser($data);
                $link = $this->userService->generateEmailLink($user);
                $mail = $this->mailService;

                $env = $mail->getSiteConfig()->getEnvironment();
                $email = $user->getEmail();
                $token = $link->getToken();

                $mail = new EmailMessage();
                $mail->setTo($user->getEmail());
                $mail->setSubject($this->getTranslator()->translate('email.user.register.thankswith', 'user') . ' ' . $this->mailService->getSiteConfig()->getTitle());
                $mail->setTemplate('email.user::user_registration/user_registration');
                $mail->setViewData([
                    'siteUrl' => $env->getSiteURL(),
                    'logo' => $this->getSiteConfig()->getEmailLogo(),
                    'activationLink' => '/user/activate/' . $email . '/' . $token,
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
     * @throws \Exception
     * @return ResponseInterface
     */
    public function editProfileAction(ServerRequestInterface $request, array $args): ResponseInterface
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
