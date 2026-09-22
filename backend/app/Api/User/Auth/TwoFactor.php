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

/*
 * Start or resume 2FA setup.
 *
 * IMPORTANT:
 * Do NOT generate a new secret every time this endpoint is opened.
 * If a setup secret already exists, reuse it so refreshing the setup page
 * cannot invalidate the QR code already scanned by the user.
 */
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

    /*
     * Read the raw value first. If it is NULL/empty, do not try to decrypt it.
     */
    $storedSecretRaw = $session->getInfo(UserColumns::TWO_FA_KEY, false);

    if ($storedSecretRaw !== '') {
        $secret = $session->getInfo(UserColumns::TWO_FA_KEY, true);
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
        [
            'secret' => $secret,
        ]
    );
});

/*
 * Verify either:
 *  - the first code during 2FA setup, or
 *  - a login-time 2FA challenge.
 *
 * Both use the same stored secret.
 */
$router->post('/api/user/auth/2fa/setup', function (): void {
    global $eventManager;

    App::init();

    $appInstance = App::getInstance(true);
    $config = $appInstance->getConfig();
    $appInstance->allowOnlyPOST();

    /*
     * Process Turnstile only when enabled.
     */
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

    $session = new Session($appInstance);

    /*
     * Check the raw DB value before decrypting it.
     */
    $storedSecretRaw = $session->getInfo(
        UserColumns::TWO_FA_KEY,
        false
    );

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

    $secret = $session->getInfo(
        UserColumns::TWO_FA_KEY,
        true
    );

    /*
     * Keep only digits and preserve leading zeroes.
     */
    $code = preg_replace(
        '/\D/',
        '',
        (string) $_POST['code']
    );

    if (strlen($code) !== 6) {
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

    /*
     * Window 1 accepts the previous/current/next 30-second TOTP window.
     * This avoids tiny clock-skew failures without weakening the flow much.
     */
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

    /*
     * A successful verification both enables 2FA (during setup)
     * and releases a login-time 2FA block.
     */
    $session->setInfo(
        UserColumns::TWO_FA_ENABLED,
        'true',
        false
    );

    $session->setInfo(
        UserColumns::TWO_FA_BLOCKED,
        'false',
        false
    );

    $eventManager->emit(
        AuthEvent::onAuth2FAVerifySuccess(),
        []
    );

    UserActivities::add(
        $session->getInfo(
            UserColumns::UUID,
            false
        ),
        UserActivitiesTypes::$two_factor_verify,
        CloudFlareRealIP::getRealIP()
    );

    $appInstance->OK(
        'Two-factor authentication verified',
        [
            'two_factor_enabled' => true,
        ]
    );
});

/*
 * Disable 2FA.
 */
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

    /*
     * The 2FA key is normally encrypted, so clear it using the
     * encrypted path as well.
     */
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
