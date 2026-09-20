<?php

/*
 * This file is part of MythicalDash.
 *
 * MIT License
 *
 * Copyright (c) 2020-2025 MythicalSystems
 * Copyright (c) 2020-2025 Cassian Gherman (NaysKutzu)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Please rather than modifying the dashboard code try to report the thing you wish on our github or write a plugin
 */

use MythicalDash\App;
use MythicalDash\Chat\User\User;
use MythicalDash\Middleware\Firewall;
use MythicalDash\Config\ConfigInterface;
use MythicalDash\Chat\columns\UserColumns;
use MythicalDash\Chat\Referral\ReferralUses;
use MythicalDash\Chat\Referral\ReferralCodes;
use MythicalDash\CloudFlare\CloudFlareRealIP;
use MythicalDash\Plugins\Events\Events\AuthEvent;
use MythicalDash\Chat\IPRelationships\IPRelationship;
use MythicalDash\Plugins\Events\Events\ReferralsEvent;
use MythicalDash\Hooks\MythicalSystems\User\UUIDManager;
use MythicalDash\Hooks\MythicalSystems\CloudFlare\Turnstile;
use MythicalDash\Services\Pterodactyl\Admin\Resources\UsersResource;

$router->add('/api/user/auth/register', function (): void {
    global $eventManager;
    global $router;

    App::init();

    $appInstance = App::getInstance(true);
    $config = $appInstance->getConfig();

    $appInstance->loadEnv();

    $setupMode = filter_var(
        $_ENV['XALIX_SETUP_MODE'] ?? 'false',
        FILTER_VALIDATE_BOOLEAN
    );

    $appInstance->allowOnlyPOST();

    if (!isset($_POST['firstName']) || $_POST['firstName'] == '') {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['firstName' => 'UNKNOWN', 'error_code' => 'MISSING_FIRST_NAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'MISSING_FIRST_NAME']);
    }

    if (!isset($_POST['lastName']) || $_POST['lastName'] == '') {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['lastName' => 'UNKNOWN', 'error_code' => 'MISSING_LAST_NAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'MISSING_LAST_NAME']);
    }

    if (!isset($_POST['email']) || $_POST['email'] == '') {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['email' => 'UNKNOWN', 'error_code' => 'MISSING_EMAIL']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'MISSING_EMAIL']);
    }

    if (!isset($_POST['password']) || $_POST['password'] == '') {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['password' => 'UNKNOWN', 'error_code' => 'MISSING_PASSWORD']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'MISSING_PASSWORD']);
    }

    if (!isset($_POST['username']) || $_POST['username'] == '') {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['username' => 'UNKNOWN', 'error_code' => 'MISSING_USERNAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'MISSING_USERNAME']);
    }

    if (!preg_match('/^[a-zA-Z]+$/', $_POST['firstName'])) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['firstName' => $_POST['firstName'], 'error_code' => 'INVALID_FIRST_NAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_FIRST_NAME']);
    }

    if (!preg_match('/^[a-zA-Z]+$/', $_POST['lastName'])) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['lastName' => $_POST['lastName'], 'error_code' => 'INVALID_LAST_NAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_LAST_NAME']);
    }

    if (!preg_match('/^[a-zA-Z0-9]+$/', $_POST['username'])) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['username' => $_POST['username'], 'error_code' => 'INVALID_USERNAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_USERNAME']);
    }

    if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['email' => $_POST['email'], 'error_code' => 'INVALID_EMAIL']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_EMAIL']);
    }

    if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $_POST['username'])) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['username' => $_POST['username'], 'error_code' => 'INVALID_USERNAME']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_USERNAME']);
    }

    if (strlen($_POST['password']) < 8) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['password' => 'REDACTED', 'error_code' => 'PASSWORD_TOO_SHORT']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'PASSWORD_TOO_SHORT']);
    }

    if (!preg_match('/^[a-z0-9]([\w\.-]+)[a-z0-9]$/i', $_POST['username'])) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['username' => $_POST['username'], 'error_code' => 'INVALID_USERNAME_FORMAT']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_USERNAME_FORMAT']);
    }

    if (strlen($_POST['username']) < 1 || strlen($_POST['username']) > 191) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['username' => $_POST['username'], 'error_code' => 'INVALID_USERNAME_LENGTH']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_USERNAME_LENGTH']);
    }

    if (strlen($_POST['email']) < 1 || strlen($_POST['email']) > 191) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['email' => $_POST['email'], 'error_code' => 'INVALID_EMAIL_LENGTH']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_EMAIL_LENGTH']);
    }

    if (strlen($_POST['firstName']) < 1 || strlen($_POST['firstName']) > 191) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['firstName' => $_POST['firstName'], 'error_code' => 'INVALID_FIRST_NAME_LENGTH']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_FIRST_NAME_LENGTH']);
    }

    if (strlen($_POST['lastName']) < 1 || strlen($_POST['lastName']) > 191) {
        $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['lastName' => $_POST['lastName'], 'error_code' => 'INVALID_LAST_NAME_LENGTH']);
        $appInstance->BadRequest('Bad Request', ['error_code' => 'INVALID_LAST_NAME_LENGTH']);
    }

    Firewall::handle($appInstance, CloudFlareRealIP::getRealIP());

    if ($config->getDBSetting(ConfigInterface::TURNSTILE_ENABLED, 'false') == 'true') {
        if (!isset($_POST['turnstileResponse']) || $_POST['turnstileResponse'] == '') {
            $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['error_code' => 'MISSING_TURNSTILE_RESPONSE']);
            $appInstance->BadRequest('Bad Request', ['error_code' => 'TURNSTILE_FAILED']);
        }

        $cfTurnstileResponse = $_POST['turnstileResponse'];

        if (!Turnstile::validate(
            $cfTurnstileResponse,
            CloudFlareRealIP::getRealIP(),
            $config->getDBSetting(ConfigInterface::TURNSTILE_KEY_PRIV, 'XXXX')
        )) {
            $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['error_code' => 'TURNSTILE_FAILED']);
            $appInstance->BadRequest('Invalid TurnStile Key', ['error_code' => 'TURNSTILE_FAILED']);
        }
    }

    $firstName = $_POST['firstName'];
    $lastName = $_POST['lastName'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $username = $_POST['username'];

    try {
        $isFirstUser = User::isFirstUserInDatabase();

        if ($setupMode && !$isFirstUser) {
            $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['error_code' => 'PTERODACTYL_NOT_ENABLED']);
            $appInstance->BadRequest(
                'Setup mode only allows the first local owner account',
                ['error_code' => 'PTERODACTYL_NOT_ENABLED']
            );
        }

        if (
            !$setupMode &&
            $config->getDBSetting(ConfigInterface::PTERODACTYL_BASE_URL, '') == ''
        ) {
            $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['error_code' => 'PTERODACTYL_NOT_ENABLED']);
            $appInstance->BadRequest(
                'Pterodactyl is not enabled',
                ['error_code' => 'PTERODACTYL_NOT_ENABLED']
            );
        }

        if (User::exists(UserColumns::USERNAME, $username)) {
            $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['error_code' => 'USERNAME_ALREADY_IN_USE']);
            $appInstance->BadRequest('Bad Request', ['error_code' => 'USERNAME_ALREADY_IN_USE']);
        }

        if (User::exists(UserColumns::EMAIL, $email)) {
            $eventManager->emit(AuthEvent::onAuthRegisterFailed(), ['error_code' => 'EMAIL_ALREADY_IN_USE']);
            $appInstance->BadRequest('Bad Request', ['error_code' => 'EMAIL_ALREADY_IN_USE']);
        }

        $pterodactylUserId = 0;

        if (!$setupMode) {
            try {
                $pterodactylUserId =
                    MythicalDash\Hooks\Pterodactyl\Admin\User::performRegister(
                        $firstName,
                        $lastName,
                        $username,
                        $email,
                        $password
                    );

                if ($pterodactylUserId <= 0) {
                    $eventManager->emit(
                        AuthEvent::onAuthRegisterFailed(),
                        ['error_code' => 'PTERODACTYL_ERROR']
                    );

                    $appInstance->InternalServerError(
                        'Internal Server Error',
                        ['error_code' => 'PTERODACTYL_ERROR']
                    );
                }

                $pteroUsers = new UsersResource(
                    $config->getDBSetting(ConfigInterface::PTERODACTYL_BASE_URL, ''),
                    $config->getDBSetting(ConfigInterface::PTERODACTYL_API_KEY, '')
                );

                MythicalDash\Hooks\Pterodactyl\Admin\User::performUpdateUser(
                    $pteroUsers,
                    $pterodactylUserId,
                    $username,
                    $firstName,
                    $lastName,
                    $email,
                    $password
                );
            } catch (Exception $e) {
                $eventManager->emit(
                    AuthEvent::onAuthRegisterFailed(),
                    ['error_code' => 'PTERODACTYL_ERROR']
                );

                $appInstance->InternalServerError(
                    'Internal Server Error',
                    ['error_code' => 'PTERODACTYL_ERROR']
                );
            }
        } else {
            $appInstance->getLogger()->warning(
                '[XalixCloud Setup Mode] Creating the first local owner account without Pterodactyl.'
            );
        }

        User::register(
            $username,
            $password,
            $email,
            $firstName,
            $lastName,
            CloudFlareRealIP::getRealIP(),
            $pterodactylUserId
        );

        $newUserUuid = User::convertEmailToUUID($email);
        $newUserToken = User::getTokenFromEmail($email);

        if ($config->getDBSetting(ConfigInterface::REFERRALS_ENABLED, false)) {
            if ($newUserUuid) {
                $referralCode = $username . '_' . $appInstance->generatePin();

                ReferralCodes::create($newUserUuid, $referralCode);

                $eventManager->emit(
                    ReferralsEvent::onReferralCreated(),
                    [
                        'user' => $newUserUuid,
                        'referral_code' => $referralCode,
                    ]
                );

                if (isset($_GET['ref']) && $_GET['ref'] != '') {
                    $referrerCode = ReferralCodes::getByCode($_GET['ref']);

                    if (
                        is_array($referrerCode) &&
                        isset($referrerCode['user']) &&
                        is_string($referrerCode['user']) &&
                        $referrerCode['user'] !== ''
                    ) {
                        $referrerUuid = $referrerCode['user'];

                        if (
                            $referrerUuid !== null &&
                            is_string($referrerUuid) &&
                            $referrerUuid !== ''
                        ) {
                            $referrerToken = User::getTokenFromUUID($referrerUuid);
                        } else {
                            $referrerToken = null;
                        }

                        if ($referrerToken == null) {
                            $eventManager->emit(
                                AuthEvent::onAuthRegisterFailed(),
                                ['error_code' => 'REFERRAL_CODE_NOT_FOUND']
                            );
                        } else {
                            ReferralUses::create(
                                $referrerCode['id'],
                                $newUserUuid
                            );

                            $eventManager->emit(
                                ReferralsEvent::onReferralRedeemed(),
                                [
                                    'user' => $referrerUuid,
                                    'referral_code' => $_GET['ref'],
                                ]
                            );

                            $newUserBonus = intval(
                                $config->getDBSetting(
                                    ConfigInterface::REFERRALS_COINS_PER_REFERRAL_REDEEMER,
                                    15
                                )
                            );

                            if (!User::addCreditsAtomic($newUserToken, $newUserBonus)) {
                                $appInstance->getLogger()->error(
                                    'Failed to add referral bonus credits atomically for new user: ' .
                                    $newUserUuid
                                );
                            }

                            $referrerBonus = intval(
                                $config->getDBSetting(
                                    ConfigInterface::REFERRALS_COINS_PER_REFERRAL,
                                    35
                                )
                            );

                            if (!User::addCreditsAtomic($referrerToken, $referrerBonus)) {
                                $appInstance->getLogger()->error(
                                    'Failed to add referral bonus credits atomically for referrer: ' .
                                    $referrerUuid
                                );
                            }
                        }
                    } else {
                        $eventManager->emit(
                            AuthEvent::onAuthRegisterFailed(),
                            ['error_code' => 'REFERRAL_CODE_NOT_FOUND']
                        );
                    }
                }
            }
        }

        $defaultRam = (int) $config->getDBSetting(ConfigInterface::DEFAULT_RAM, 1024);
        $defaultDisk = (int) $config->getDBSetting(ConfigInterface::DEFAULT_DISK, 1024);
        $defaultCpu = (int) $config->getDBSetting(ConfigInterface::DEFAULT_CPU, 100);
        $defaultPorts = (int) $config->getDBSetting(ConfigInterface::DEFAULT_PORTS, 2);
        $defaultDatabases = (int) $config->getDBSetting(ConfigInterface::DEFAULT_DATABASES, 1);
        $defaultServerSlots = (int) $config->getDBSetting(ConfigInterface::DEFAULT_SERVER_SLOTS, 1);
        $defaultBackups = (int) $config->getDBSetting(ConfigInterface::DEFAULT_BACKUPS, 5);
        $defaultBg = $config->getDBSetting(
            ConfigInterface::DEFAULT_BG,
            'https://cdn.mythical.systems/mc.jpg'
        );

        if ($defaultDatabases > 0) {
            $defaultDatabases = 1;
        }

        if ($defaultServerSlots > 0) {
            $defaultServerSlots = 1;
        }

        if ($defaultBackups > 0) {
            $defaultBackups = 1;
        }

        if ($defaultPorts > 0) {
            $defaultPorts = 1;
        }

        User::updateInfo($newUserToken, UserColumns::MEMORY_LIMIT, $defaultRam, false);
        User::updateInfo($newUserToken, UserColumns::DISK_LIMIT, $defaultDisk, false);
        User::updateInfo($newUserToken, UserColumns::CPU_LIMIT, $defaultCpu, false);
        User::updateInfo($newUserToken, UserColumns::ALLOCATION_LIMIT, $defaultPorts, false);
        User::updateInfo($newUserToken, UserColumns::DATABASE_LIMIT, $defaultDatabases, false);
        User::updateInfo($newUserToken, UserColumns::SERVER_LIMIT, $defaultServerSlots, false);
        User::updateInfo($newUserToken, UserColumns::BACKUP_LIMIT, $defaultBackups, false);
        User::updateInfo($newUserToken, UserColumns::BACKGROUND, $defaultBg, false);

        $eventManager->emit(
            AuthEvent::onAuthRegisterSuccess(),
            ['username' => $username, 'email' => $email]
        );

        if (
            $config->getDBSetting(
                ConfigInterface::IMAGE_HOSTING_ENABLED,
                'false'
            ) === 'true'
        ) {
            $api_key = UUIDManager::generateUUID();

            User::updateInfo(
                $newUserToken,
                UserColumns::IMAGE_HOSTING_UPLOAD_KEY,
                $api_key,
                false
            );

            $appInstance->getLogger()->debug(
                'Generated image hosting API key for new user: ' .
                $username
            );
        }

        IPRelationship::create(
            $newUserUuid,
            CloudFlareRealIP::getRealIP()
        );

        App::OK(
            'User registered',
            [
                'is_first_user' => $isFirstUser,
                'setup_mode' => $setupMode,
            ]
        );
    } catch (Exception $e) {
        $eventManager->emit(
            AuthEvent::onAuthRegisterFailed(),
            ['error_code' => 'DATABASE_ERROR']
        );

        $appInstance->InternalServerError(
            'Internal Server Error',
            ['error_code' => 'DATABASE_ERROR']
        );
    }
});
