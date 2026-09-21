<?php

/*
 * This file is part of MythicalDash.
 *
 * MIT License
 *
 * Copyright (c) 2020-2025 MythicalSystems
 * Copyright (c) 2020-2025 Cassian Gherman (NaysKutzu)
 */

namespace MythicalDash\Api\User\Auth;

use MythicalDash\App;
use MythicalDash\Mail\Mail;
use MythicalDash\Chat\User\User;
use MythicalDash\Chat\Servers\Server;
use MythicalDash\Middleware\Firewall;
use MythicalDash\Config\ConfigInterface;
use MythicalDash\Chat\columns\UserColumns;
use MythicalDash\Chat\User\PermissionUtils;
use MythicalDash\CloudFlare\CloudFlareRealIP;
use MythicalDash\Hooks\Pterodactyl\Admin\Servers;
use MythicalDash\Plugins\Events\Events\AuthEvent;
use MythicalDash\Chat\IPRelationships\IPRelationship;
use MythicalDash\Hooks\MythicalSystems\User\UUIDManager;
use MythicalDash\Hooks\MythicalSystems\CloudFlare\Turnstile;

$router->add('/api/user/auth/login', function (): void {
    global $eventManager;
    global $router;

    $appInstance = App::getInstance(true);
    $config = $appInstance->getConfig();

    $appInstance->loadEnv();

    $setupMode = filter_var(
        $_ENV['XALIX_SETUP_MODE'] ?? 'false',
        FILTER_VALIDATE_BOOLEAN
    );

    $appInstance->allowOnlyPOST();

    if (!isset($_POST['login']) || $_POST['login'] == '') {
        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => 'UNKNOWN',
                'error_code' => 'MISSING_LOGIN',
            ]
        );

        $appInstance->BadRequest(
            'Bad Request',
            ['error_code' => 'MISSING_LOGIN']
        );
    }

    if (!isset($_POST['password']) || $_POST['password'] == '') {
        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => $_POST['login'],
                'error_code' => 'MISSING_PASSWORD',
            ]
        );

        $appInstance->BadRequest(
            'Bad Request',
            ['error_code' => 'MISSING_PASSWORD']
        );
    }

    if (
        $config->getDBSetting(
            ConfigInterface::TURNSTILE_ENABLED,
            'false'
        ) == 'true'
    ) {
        if (
            !isset($_POST['turnstileResponse']) ||
            $_POST['turnstileResponse'] == ''
        ) {
            $eventManager->emit(
                AuthEvent::onAuthLoginFailed(),
                [
                    'login' => $_POST['login'],
                    'error_code' => 'TURNSTILE_FAILED',
                ]
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
                AuthEvent::onAuthLoginFailed(),
                [
                    'login' => $_POST['login'],
                    'error_code' => 'TURNSTILE_FAILED',
                ]
            );

            $appInstance->BadRequest(
                'Invalid TurnStile Key',
                ['error_code' => 'TURNSTILE_FAILED']
            );
        }
    }

    $login = $_POST['login'];
    $password = $_POST['password'];

    Firewall::handle(
        $appInstance,
        CloudFlareRealIP::getRealIP()
    );

    $loginResult = User::login(
        $login,
        $password
    );

    if ($loginResult == 'false') {
        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => $login,
                'error_code' => 'INVALID_CREDENTIALS',
            ]
        );

        $appInstance->BadRequest(
            'Invalid login credentials',
            ['error_code' => 'INVALID_CREDENTIALS']
        );
    }

    if (
        !$setupMode &&
        $config->getDBSetting(
            ConfigInterface::PTERODACTYL_BASE_URL,
            ''
        ) == ''
    ) {
        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => $login,
                'error_code' => 'PTERODACTYL_NOT_ENABLED',
            ]
        );

        $appInstance->BadRequest(
            'Pterodactyl is not enabled',
            ['error_code' => 'PTERODACTYL_NOT_ENABLED']
        );
    }

    try {
        $userInfoArray = User::getInfoArray(
            $loginResult,
            [
                UserColumns::PTERODACTYL_USER_ID,
                UserColumns::VERIFIED,
                UserColumns::BANNED,
                UserColumns::DELETED,
                UserColumns::USERNAME,
                UserColumns::TWO_FA_ENABLED,
                UserColumns::TWO_FA_BLOCKED,
                UserColumns::EMAIL,
                UserColumns::PASSWORD,
                UserColumns::UUID,
                UserColumns::FIRST_NAME,
                UserColumns::LAST_NAME,
                UserColumns::CREDITS,
                UserColumns::DISCORD_ID,
                UserColumns::GITHUB_ID,
                UserColumns::AVATAR,
                UserColumns::IMAGE_HOSTING_UPLOAD_KEY,
            ],
            [
                UserColumns::FIRST_NAME,
                UserColumns::LAST_NAME,
                UserColumns::PASSWORD,
            ]
        );

        $criticalFields = [
            UserColumns::USERNAME => 'username',
            UserColumns::EMAIL => 'email',
            UserColumns::UUID => 'UUID',
        ];

        if (!$setupMode) {
            $criticalFields[
                UserColumns::PTERODACTYL_USER_ID
            ] = 'Pterodactyl user ID';
        }

        foreach ($criticalFields as $field => $fieldName) {
            if (
                !isset($userInfoArray[$field]) ||
                $userInfoArray[$field] === null ||
                $userInfoArray[$field] === ''
            ) {
                $appInstance->getLogger()->error(
                    "Critical user data missing: {$fieldName} for user {$login}"
                );

                $eventManager->emit(
                    AuthEvent::onAuthLoginFailed(),
                    [
                        'login' => $login,
                        'error_code' => 'INVALID_USER_DATA',
                    ]
                );

                $appInstance->BadRequest(
                    'Invalid user data',
                    ['error_code' => 'INVALID_USER_DATA']
                );
            }
        }
    } catch (\Exception $e) {
        $appInstance->getLogger()->error(
            'Failed to get user info: ' .
            $e->getMessage()
        );

        $appInstance->InternalServerError(
            'Internal Server Error',
            ['error_code' => 'DATABASE_ERROR']
        );
    }

    /*
     * Once setup mode is disabled, automatically
     * connect the local XalixCloud owner account
     * to Pterodactyl if it has no Pterodactyl ID.
     */
    if (
        !$setupMode &&
        (int) $userInfoArray[
            UserColumns::PTERODACTYL_USER_ID
        ] === 0
    ) {
        try {
            $newPterodactylUserId =
                \MythicalDash\Hooks\Pterodactyl\Admin\User::performRegister(
                    $userInfoArray[
                        UserColumns::FIRST_NAME
                    ] ?? '',
                    $userInfoArray[
                        UserColumns::LAST_NAME
                    ] ?? '',
                    $userInfoArray[
                        UserColumns::USERNAME
                    ],
                    $userInfoArray[
                        UserColumns::EMAIL
                    ],
                    $userInfoArray[
                        UserColumns::PASSWORD
                    ] ?? ''
                );

            if ($newPterodactylUserId <= 0) {
                throw new \Exception(
                    'Pterodactyl returned an invalid user ID'
                );
            }

            User::updateInfo(
                $loginResult,
                UserColumns::PTERODACTYL_USER_ID,
                $newPterodactylUserId,
                false
            );

            $userInfoArray[
                UserColumns::PTERODACTYL_USER_ID
            ] = $newPterodactylUserId;

            $appInstance->getLogger()->info(
                '[XalixCloud Setup Mode] Linked local user to Pterodactyl user ID ' .
                $newPterodactylUserId
            );
        } catch (\Exception $e) {
            $appInstance->getLogger()->error(
                '[XalixCloud Setup Mode] Failed to link local user to Pterodactyl: ' .
                $e->getMessage()
            );

            $eventManager->emit(
                AuthEvent::onAuthLoginFailed(),
                [
                    'login' => $login,
                    'error_code' => 'PTERODACTYL_ERROR',
                ]
            );

            $appInstance->InternalServerError(
                'Internal Server Error',
                ['error_code' => 'PTERODACTYL_ERROR']
            );
        }
    }

    /*
     * Verification checks.
     */
    if (
        ($userInfoArray[
            UserColumns::VERIFIED
        ] ?? 'false') == 'false' &&
        Mail::isEnabled()
    ) {
        User::logout();

        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => $login,
                'error_code' => 'ACCOUNT_NOT_VERIFIED',
            ]
        );

        $appInstance->BadRequest(
            'Account not verified',
            ['error_code' => 'ACCOUNT_NOT_VERIFIED']
        );
    }

    if (
        ($userInfoArray[
            UserColumns::BANNED
        ] ?? 'NO') !== 'NO'
    ) {
        User::logout();

        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => $login,
                'error_code' => 'ACCOUNT_BANNED',
            ]
        );

        $appInstance->BadRequest(
            'Account is banned',
            ['error_code' => 'ACCOUNT_BANNED']
        );
    }

    if (
        ($userInfoArray[
            UserColumns::DELETED
        ] ?? 'false') == 'true'
    ) {
        User::logout();

        $eventManager->emit(
            AuthEvent::onAuthLoginFailed(),
            [
                'login' => $login,
                'error_code' => 'ACCOUNT_DELETED',
            ]
        );

        $appInstance->BadRequest(
            'Account is deleted',
            ['error_code' => 'ACCOUNT_DELETED']
        );
    }

    /*
     * Determine whether this login requires 2FA.
     */
    $requiresTwoFactor =
        (
            $userInfoArray[
                UserColumns::TWO_FA_ENABLED
            ] ?? 'false'
        ) === 'true';

    if ($requiresTwoFactor) {
        User::updateInfo(
            $loginResult,
            UserColumns::TWO_FA_BLOCKED,
            'true',
            false
        );
    }

    /*
     * Set the session cookie BEFORE returning the
     * 2FA-required response, because the verification
     * endpoint needs this token.
     */
    if (APP_DEBUG) {
        setcookie(
            'user_token',
            $loginResult,
            time() + 3600 * 31 * 3600,
            '/'
        );
    } else {
        setcookie(
            'user_token',
            $loginResult,
            time() + 3600,
            '/'
        );
    }

    /*
     * Password was correct, but do NOT enter the
     * dashboard yet if 2FA is enabled.
     */
    if ($requiresTwoFactor) {
        $eventManager->emit(
            AuthEvent::onAuthLoginSuccess(),
            [
                'login' =>
                    $userInfoArray[
                        UserColumns::EMAIL
                    ],
            ]
        );

        $appInstance->OK(
            'Two-factor authentication required',
            [
                'requires_2fa' => true,
            ]
        );
    }

    /*
     * Pterodactyl login/server syncing only runs
     * outside temporary Xalix setup mode.
     */
    if (!$setupMode) {
        try {
            \MythicalDash\Hooks\Pterodactyl\Admin\User::performLogin(
                $userInfoArray[
                    UserColumns::PTERODACTYL_USER_ID
                ],
                $userInfoArray[
                    UserColumns::EMAIL
                ],
                $userInfoArray[
                    UserColumns::USERNAME
                ],
                $userInfoArray[
                    UserColumns::FIRST_NAME
                ] ?? '',
                $userInfoArray[
                    UserColumns::LAST_NAME
                ] ?? '',
                $userInfoArray[
                    UserColumns::PASSWORD
                ] ?? ''
            );
        } catch (\Exception $e) {
            $appInstance->getLogger()->error(
                '[Pterodactyl/Admin/User#performLogin] ' .
                $e->getMessage()
            );

            $appInstance->InternalServerError(
                'Internal Server Error',
                ['error_code' => 'PTERODACTYL_ERROR']
            );
        }

        try {
            $pterodactylServers =
                Servers::getUserServersList(
                    $userInfoArray[
                        UserColumns::PTERODACTYL_USER_ID
                    ]
                );

            foreach (
                $pterodactylServers
                as $pterodactylServer
            ) {
                if (
                    !Server::doesServerExistByPterodactylId(
                        $pterodactylServer['id']
                    )
                ) {
                    Server::create(
                        $pterodactylServer['id'],
                        null,
                        $userInfoArray[
                            UserColumns::UUID
                        ]
                    );
                }
            }
        } catch (\Exception $e) {
            $appInstance->getLogger()->error(
                '[Pterodactyl server sync] ' .
                $e->getMessage()
            );

            $appInstance->InternalServerError(
                'Internal Server Error',
                ['error_code' => 'PTERODACTYL_ERROR']
            );
        }
    } else {
        $appInstance->getLogger()->warning(
            '[XalixCloud Setup Mode] Pterodactyl login and server sync skipped.'
        );
    }

    $userUuid =
        $userInfoArray[
            UserColumns::UUID
        ];

    $currentIP =
        CloudFlareRealIP::getRealIP();

    $hasAltBypassPermission =
        PermissionUtils::userHasPermission(
            $loginResult,
            \MythicalDash\Permissions::USER_PERMISSION_BYPASS_ALTING
        );

    if (
        $config->getDBSetting(
            ConfigInterface::FIREWALL_BLOCK_ALTS,
            'false'
        ) == 'true' &&
        !$hasAltBypassPermission
    ) {
        $processedUsers = [];

        IPRelationship::create(
            $userUuid,
            $currentIP
        );

        $multipleAccounts =
            IPRelationship::processMultipleAccounts(
                $userUuid
            );

        if (
            $multipleAccounts[
                'has_multiple_accounts'
            ]
        ) {
            try {
                User::updateInfo(
                    $loginResult,
                    UserColumns::BANNED,
                    'User banned for multiple accounts on ' .
                    $currentIP,
                    false
                );

                $processedUsers[] = [
                    'uuid' =>
                        $userUuid,
                    'username' =>
                        $userInfoArray[
                            UserColumns::USERNAME
                        ],
                    'avatar' =>
                        $userInfoArray[
                            UserColumns::AVATAR
                        ],
                ];
            } catch (\Exception $e) {
                $appInstance
                    ->getLogger()
                    ->error(
                        'Failed to ban current user: ' .
                        $e->getMessage()
                    );
            }

            foreach (
                $multipleAccounts[
                    'relationships'
                ]
                as $relationship
            ) {
                try {
                    $token =
                        User::getTokenFromUUID(
                            $relationship['user']
                        );

                    $relatedUserInfo =
                        User::getInfoArray(
                            $token,
                            [
                                UserColumns::USERNAME,
                                UserColumns::AVATAR,
                            ],
                            [
                                UserColumns::PASSWORD,
                            ]
                        );

                    User::updateInfo(
                        $token,
                        UserColumns::BANNED,
                        'User banned for multiple accounts on ' .
                        $currentIP,
                        false
                    );

                    $processedUsers[] = [
                        'uuid' =>
                            $relationship['user'],
                        'username' =>
                            $relatedUserInfo[
                                UserColumns::USERNAME
                            ],
                        'avatar' =>
                            $relatedUserInfo[
                                UserColumns::AVATAR
                            ],
                    ];
                } catch (\Exception $e) {
                    $appInstance
                        ->getLogger()
                        ->error(
                            'Failed to ban related user: ' .
                            $e->getMessage()
                        );
                }
            }
        }

        if (!empty($processedUsers)) {
            $appInstance->BadRequest(
                'Multiple accounts detected and banned',
                [
                    'error_code' =>
                        'MULTIPLE_ACCOUNTS',
                    'info' =>
                        $processedUsers,
                ]
            );
        }
    }

    $login =
        $userInfoArray[
            UserColumns::EMAIL
        ];

    if (
        $config->getDBSetting(
            ConfigInterface::IMAGE_HOSTING_ENABLED,
            'false'
        ) === 'true'
    ) {
        $api_key =
            $userInfoArray[
                UserColumns::IMAGE_HOSTING_UPLOAD_KEY
            ] ?? '';

        if (empty($api_key)) {
            $api_key =
                UUIDManager::generateUUID();

            User::updateInfo(
                $loginResult,
                UserColumns::IMAGE_HOSTING_UPLOAD_KEY,
                $api_key,
                false
            );
        }
    }

    $eventManager->emit(
        AuthEvent::onAuthLoginSuccess(),
        [
            'login' => $login,
        ]
    );

    $appInstance->OK(
        'Successfully logged in',
        [
            'requires_2fa' => false,
        ]
    );
});
