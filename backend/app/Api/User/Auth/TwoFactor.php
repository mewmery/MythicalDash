<?php

/*
 * This file is part of MythicalDash.
 *
 * MIT License
 *
 * Copyright (c) 2020-2025 MythicalSystems
 * Copyright (c) 2020-2025 Cassian Gherman (NaysKutzu)
 */

use MythicalDash\App;
use MythicalDash\Chat\User\User;
use PragmaRX\Google2FA\Google2FA;
use MythicalDash\Chat\User\Session;
use MythicalDash\Middleware\Firewall;
use MythicalDash\Config\ConfigInterface;
use MythicalDash\Chat\columns\UserColumns;
use MythicalDash\Chat\User\UserActivities;
use MythicalDash\CloudFlare\CloudFlareRealIP;
use MythicalDash\Plugins\Events\Events\AuthEvent;
use MythicalDash\Chat\interface\UserActivitiesTypes;
use MythicalDash\Hooks\MythicalSystems\CloudFlare\Turnstile;

$router->get('/api/user/auth/2fa/setup', function (): void {
    App::init();

    $appInstance = App::getInstance(true);
    $appInstance->allowOnlyGET();

    $session = new Session($appInstance);

    if ($session->getInfo(UserColumns::TWO_FA_ENABLED, false) === 'true') {
        $appInstance->BadRequest(
            'Two-factor authentication is already enabled',
            ['error_code' => 'TWO_FA_ALREADY_ENABLED']
        );
    }

    $storedSecretRaw = $session->getInfo(
        UserColumns::TWO_FA_KEY,
        false
    );

    if ($storedSecretRaw !== '') {
        $secret = $session->getInfo(
            UserColumns::TWO_FA_KEY,
            true
        );
    } else {
        $google2fa = new Google2FA();
        $secret = $google2fa->generateSecretKey();

        $session->setInfo(
            UserColumns::TWO_FA_KEY,
            $secret,
            true
        );
    }

    $appInstance->OK(
        'Two-factor setup ready',
        ['secret' => $secret]
    );
});

$router->post('/api/user/auth/2fa/setup', function (): void {
    global $eventManager;

    App::init();

    $appInstance = App::getInstance(true);
    $config = $appInstance->getConfig();
    $appInstance->allowOnlyPOST();

    /*
     * IMPORTANT:
     * Do not create a Session here.
     *
     * Session rejects users while 2fa_blocked=true. That is correct for
     * normal authenticated endpoints, but this endpoint is the one that
     * must accept the TOTP code and clear 2fa_blocked.
     */
    if (
        !isset($_COOKIE['user_token']) ||
        $_COOKIE['user_token'] === ''
    ) {
        $appInstance->Unauthorized(
            'Please tell me who you are.',
            ['error_code' => 'MISSING_ACCOUNT_TOKEN']
        );
    }

    $token = (string) $_COOKIE['user_token'];

    if (
        !User::exists(
            UserColumns::ACCOUNT_TOKEN,
            $token
        )
    ) {
        $appInstance->Unauthorized(
            'Login info provided are invalid!',
            ['error_code' => 'INVALID_ACCOUNT_TOKEN']
        );
    }

    if (
        $config->getDBSetting(
            ConfigInterface::TURNSTILE_ENABLED,
            'false'
        ) === 'true'
    ) {
        if (
            !isset($_POST['turnstileResponse']) ||
            $_POST['turnstileResponse'] === ''
        ) {
            $eventManager->emit(
                AuthEvent::onAuth2FAVerifyFailed(),
                ['error_code' => 'TURNSTILE_FAILED']
            );

            $appInstance->BadRequest(
                'Bad Request',
                ['error_code' => 'TURNSTILE_FAILED']
            );
        }

        $cfTurnstileResponse = $_POST['turnstileResponse'];

        if (
            !Turnstile::validate(
                $cfTurnstileResponse,
                CloudFlareRealIP::getRealIP(),
                $config->getDBSetting(
                    ConfigInterface::TURNSTILE_KEY_PRIV,
                    'XXXX'
                )
            )
        ) {
            $eventManager->emit(
                AuthEvent::onAuth2FAVerifyFailed(),
                ['error_code' => 'TURNSTILE_FAILED']
            );

            $appInstance->BadRequest(
                'Invalid TurnStile Key',
                ['error_code' => 'TURNSTILE_FAILED']
            );
        }
    }

    Firewall::handle(
        $appInstance,
        CloudFlareRealIP::getRealIP()
    );

    if (
        !isset($_POST['code']) ||
        $_POST['code'] === ''
    ) {
        $eventManager->emit(
            AuthEvent::onAuth2FAVerifyFailed(),
            ['error_code' => 'MISSING_CODE']
        );

        $appInstance->BadRequest(
            'Code is required',
            ['error_code' => 'MISSING_CODE']
        );
    }

    $storedSecretRaw = User::getInfo(
        $token,
        UserColumns::TWO_FA_KEY,
        false
    ) ?? '';

    if ($storedSecretRaw === '') {
        $eventManager->emit(
            AuthEvent::onAuth2FAVerifyFailed(),
            ['error_code' => 'TWO_FA_NOT_INITIALIZED']
        );

        $appInstance->BadRequest(
            'Two-factor authentication has not been initialized',
            ['error_code' => 'TWO_FA_NOT_INITIALIZED']
        );
    }

    $secret = User::getInfo(
        $token,
        UserColumns::TWO_FA_KEY,
        true
    ) ?? '';

    if ($secret === '') {
        $eventManager->emit(
            AuthEvent::onAuth2FAVerifyFailed(),
            ['error_code' => 'TWO_FA_NOT_INITIALIZED']
        );

        $appInstance->BadRequest(
            'Two-factor authentication has not been initialized',
            ['error_code' => 'TWO_FA_NOT_INITIALIZED']
        );
    }

    $code = preg_replace(
        '/\D/',
        '',
        (string) $_POST['code']
    );

    if (
        $code === null ||
        strlen($code) !== 6
    ) {
        $eventManager->emit(
            AuthEvent::onAuth2FAVerifyFailed(),
            ['error_code' => 'INVALID_CODE']
        );

        $appInstance->Unauthorized(
            'Invalid code',
            ['error_code' => 'INVALID_CODE']
        );
    }

    $google2fa = new Google2FA();

    $valid = $google2fa->verifyKey(
        $secret,
        $code,
        1
    );

    if (!$valid) {
        $eventManager->emit(
            AuthEvent::onAuth2FAVerifyFailed(),
            ['error_code' => 'INVALID_CODE']
        );

        $appInstance->Unauthorized(
            'Invalid code',
            ['error_code' => 'INVALID_CODE']
        );
    }

    User::updateInfo(
        $token,
        UserColumns::TWO_FA_ENABLED,
        'true',
        false
    );

    User::updateInfo(
        $token,
        UserColumns::TWO_FA_BLOCKED,
        'false',
        false
    );

    $eventManager->emit(
        AuthEvent::onAuth2FAVerifySuccess(),
        []
    );

    $uuid = User::getInfo(
        $token,
        UserColumns::UUID,
        false
    ) ?? '';

    if ($uuid !== '') {
        UserActivities::add(
            $uuid,
            UserActivitiesTypes::$two_factor_verify,
            CloudFlareRealIP::getRealIP()
        );
    }

    $appInstance->OK(
        'Two-factor authentication verified',
        [
            'two_factor_enabled' => true,
            'two_factor_blocked' => false,
        ]
    );
});

$router->get('/api/auth/2fa/setup/kill', function (): void {
    App::init();

    $appInstance = App::getInstance(true);
    $appInstance->allowOnlyGET();

    $session = new Session($appInstance);

    $session->setInfo(
        UserColumns::TWO_FA_ENABLED,
        'false',
        false
    );

    $session->setInfo(
        UserColumns::TWO_FA_BLOCKED,
        'false',
        false
    );

    $session->setInfo(
        UserColumns::TWO_FA_KEY,
        '',
        true
    );

    UserActivities::add(
        $session->getInfo(
            UserColumns::UUID,
            false
        ),
        UserActivitiesTypes::$two_factor_disable,
        CloudFlareRealIP::getRealIP()
    );

    header('Location: /account?tab=Security');
    exit;
});
