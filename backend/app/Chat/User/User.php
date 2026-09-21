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

namespace MythicalDash\Chat\User;

use MythicalDash\App;
use Gravatar\Gravatar;
use MythicalDash\Mail\Mail;
use MythicalDash\Chat\Database;
use MythicalDash\Mail\templates\Verify;
use MythicalDash\Config\ConfigInterface;
use MythicalDash\Mail\templates\NewLogin;
use MythicalDash\Chat\columns\UserColumns;
use MythicalDash\Mail\templates\ResetPassword;
use MythicalDash\Chat\columns\EmailVerificationColumns;

class User extends Database
{
    public const TABLE_NAME = 'mythicaldash_users';

    public static function getTableName(): string
    {
        return self::TABLE_NAME;
    }

    /**
     * Register a new user in the database.
     */
    public static function register(
        string $username,
        string $password,
        string $email,
        string $first_name,
        string $last_name,
        string $ip,
        int $pterodactylUserId
    ): void {
        $config = App::getInstance(true)->getConfig();

        try {
            $appInstance = App::getInstance(true);

            $first_name = $appInstance->encrypt($first_name);
            $last_name = $appInstance->encrypt($last_name);

            $uuidMngr =
                new \MythicalDash\Hooks\MythicalSystems\User\UUIDManager();

            $uuid = $uuidMngr->generateUUID();

            $token = App::getInstance(true)->encrypt(
                date('Y-m-d H:i:s') .
                $uuid .
                random_bytes(16) .
                base64_encode($email)
            );

            try {
                $gravatar = new Gravatar(['s' => 9001], true);
                $avatar = $gravatar->avatar($email);
            } catch (\Exception) {
                $avatar = 'https://www.gravatar.com/avatar';
            }

            $pdoConnection = self::getPdoConnection();

            $stmt = $pdoConnection->prepare('
                INSERT INTO ' . self::TABLE_NAME . '
                (
                    username,
                    first_name,
                    last_name,
                    email,
                    password,
                    avatar,
                    background,
                    uuid,
                    pterodactyl_user_id,
                    token,
                    role,
                    first_ip,
                    last_ip,
                    banned,
                    verified,
                    support_pin
                )
                VALUES
                (
                    :username,
                    :first_name,
                    :last_name,
                    :email,
                    :password,
                    :avatar,
                    :background,
                    :uuid,
                    :pterodactyl_user_id,
                    :token,
                    :role,
                    :first_ip,
                    :last_ip,
                    :banned,
                    :verified,
                    :support_pin
                )
            ');

            $password =
                App::getInstance(true)->encrypt($password);

            $stmt->execute([
                ':username' => $username,
                ':first_name' => $first_name,
                ':last_name' => $last_name,
                ':email' => $email,
                ':password' => $password,
                ':avatar' => $avatar,
                ':background' =>
                    'https://cdn.mythical.systems/background.gif',
                ':uuid' => $uuid,
                ':pterodactyl_user_id' =>
                    $pterodactylUserId,
                ':token' => $token,
                ':role' => 1,
                ':first_ip' => $ip,
                ':last_ip' => $ip,
                ':banned' => 'NO',
                ':verified' => 'false',
                ':support_pin' =>
                    App::getInstance(true)->generatePin(),
            ]);

            if (Mail::isEnabled()) {
                try {
                    if (
                        $config->getDBSetting(
                            ConfigInterface::FORCE_MAIL_LINK,
                            'false'
                        ) == 'true'
                    ) {
                        $verify_token =
                            App::getInstance(true)->generateCode();

                        $appInstance
                            ->getLogger()
                            ->debug(
                                'Verify token: ' .
                                $verify_token
                            );

                        Verification::add(
                            $verify_token,
                            $uuid,
                            EmailVerificationColumns::$type_verify
                        );

                        $appInstance
                            ->getLogger()
                            ->debug('Verification added');

                        Verify::sendMail(
                            $uuid,
                            $verify_token
                        );

                        $appInstance
                            ->getLogger()
                            ->debug('Email sent');
                    } else {
                        self::updateInfo(
                            $token,
                            UserColumns::VERIFIED,
                            'true',
                            false
                        );
                    }
                } catch (\Exception $e) {
                    App::getInstance(true)
                        ->getLogger()
                        ->error(
                            'Failed to send email: ' .
                            $e->getMessage()
                        );

                    $appInstance
                        ->getLogger()
                        ->debug('Failed to send email');

                    self::updateInfo(
                        $token,
                        UserColumns::VERIFIED,
                        'false',
                        false
                    );
                }
            } else {
                self::updateInfo(
                    $token,
                    UserColumns::VERIFIED,
                    'true',
                    false
                );
            }

            /*
             * First registered MythicalDash user becomes owner.
             */
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT id
                 FROM ' . self::TABLE_NAME . '
                 WHERE uuid = :uuid'
            );

            $stmt->bindParam(':uuid', $uuid);
            $stmt->execute();

            $userRow =
                $stmt->fetch(\PDO::FETCH_ASSOC);

            if (
                $userRow &&
                isset($userRow['id']) &&
                (int) $userRow['id'] === 1
            ) {
                self::updateInfo(
                    $token,
                    UserColumns::ROLE_ID,
                    8,
                    false
                );
            }
        } catch (\Exception $e) {
            App::getInstance(true)
                ->getLogger()
                ->error(
                    'Failed to register user: ' .
                    $e->getMessage()
                );

            throw new \Exception(
                'Failed to register user: ' .
                $e->getMessage()
            );
        }
    }

    /**
     * Check if the user is the first user in the database.
     */
    public static function isFirstUserInDatabase(): bool
    {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT COUNT(*) AS count
                 FROM ' . self::TABLE_NAME . '
                 WHERE deleted = :deleted'
            );

            $stmt->execute([
                ':deleted' => 'false',
            ]);

            $result =
                $stmt->fetch(\PDO::FETCH_ASSOC);

            return (int) ($result['count'] ?? 0) === 0;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to check if user is first in database: ' .
                $e->getMessage()
            );

            return false;
        }
    }

    public static function getListWithFilters(
        array $rows,
        array $encrypted
    ): array {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT ' .
                implode(', ', $rows) .
                ' FROM ' .
                self::TABLE_NAME .
                ' WHERE deleted = "false"
                  ORDER BY id ASC'
            );

            $stmt->execute();

            $users =
                $stmt->fetchAll(\PDO::FETCH_ASSOC);

            foreach ($users as &$user) {
                foreach ($rows as $row) {
                    if (in_array($row, $encrypted)) {
                        $user[$row] =
                            App::getInstance(true)
                                ->decrypt($user[$row]);
                    }
                }
            }

            return $users;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get user list: ' .
                $e->getMessage()
            );

            return [];
        }
    }

    public static function getUserByUuid(
        string $uuid
    ): ?array {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT *
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE uuid = :uuid'
            );

            $stmt->bindParam(':uuid', $uuid);
            $stmt->execute();

            return
                $stmt->fetch(\PDO::FETCH_ASSOC)
                ?: null;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get user by uuid: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getList(): array
    {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT *
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE deleted = "false"
                 ORDER BY id ASC'
            );

            $stmt->execute();

            $users =
                $stmt->fetchAll(\PDO::FETCH_ASSOC);

            foreach ($users as &$user) {
                if (isset($user['first_name'])) {
                    $user['first_name'] =
                        App::getInstance(true)
                            ->decrypt(
                                $user['first_name']
                            );
                }

                if (isset($user['last_name'])) {
                    $user['last_name'] =
                        App::getInstance(true)
                            ->decrypt(
                                $user['last_name']
                            );
                }
            }

            return $users;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get user list: ' .
                $e->getMessage()
            );

            return [];
        }
    }

    public static function forgotPassword(
        string $email
    ): bool {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT token, uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE email = :email'
            );

            $stmt->bindParam(':email', $email);
            $stmt->execute();

            $user =
                $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($user) {
                if (Mail::isEnabled()) {
                    try {
                        $verify_token =
                            App::getInstance(true)
                                ->generateCode();

                        Verification::add(
                            $verify_token,
                            $user['uuid'],
                            EmailVerificationColumns::$type_password
                        );

                        ResetPassword::sendMail(
                            $user['uuid'],
                            $verify_token
                        );
                    } catch (\Exception $e) {
                        App::getInstance(true)
                            ->getLogger()
                            ->error(
                                'Failed to send email: ' .
                                $e->getMessage()
                            );
                    }

                    return true;
                }

                return false;
            }

            return false;
        } catch (\Exception $e) {
            return false;
        }
    }

    public static function login(
        string $login,
        string $password
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT password, token, uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE username = :login
                    OR email = :login'
            );

            $stmt->bindParam(':login', $login);
            $stmt->execute();

            $user =
                $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($user) {
                if (
                    App::getInstance(true)
                        ->decrypt($user['password'])
                    == $password
                ) {
                    self::logout();

                    if (!$user['token'] == '') {
                        setcookie(
                            'user_token',
                            $user['token'],
                            time() + 3600,
                            '/'
                        );
                    } else {
                        App::getInstance(true)
                            ->getLogger()
                            ->error(
                                'Failed to login user: Token is empty'
                            );

                        return 'false';
                    }

                    if (Mail::isEnabled()) {
                        try {
                            NewLogin::sendMail(
                                $user['uuid']
                            );
                        } catch (\Exception $e) {
                            App::getInstance(true)
                                ->getLogger()
                                ->error(
                                    'Failed to send email: ' .
                                    $e->getMessage()
                                );
                        }
                    }

                    return $user['token'];
                }

                return 'false';
            }

            return 'false';
        } catch (\Exception $e) {
            App::getInstance(true)
                ->getLogger()
                ->error(
                    'Failed to login user: ' .
                    $e->getMessage()
                );

            return 'false';
        }
    }

    public static function logout(): void
    {
        setcookie(
            'user_token',
            '',
            time() - 460800 * 460800 * 460800,
            '/'
        );
    }

    public static function exists(
        UserColumns|string $info,
        string $value,
        bool $doNotIncludeDeleted = false
    ): bool {
        try {
            if (
                !in_array(
                    $info,
                    UserColumns::getColumns()
                )
            ) {
                throw new \InvalidArgumentException(
                    'Invalid column name: ' .
                    $info
                );
            }

            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT *
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE ' .
                $info .
                ' = :value' .
                (
                    $doNotIncludeDeleted
                    ? ' AND deleted = "false"'
                    : ''
                )
            );

            $stmt->bindParam(':value', $value);
            $stmt->execute();

            return (bool)
                $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to check if user exists: ' .
                $e->getMessage()
            );

            return false;
        }
    }

    public static function checkSupportPin(
        string $supportPin
    ): bool {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT *
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE support_pin = :supportPin'
            );

            $stmt->bindParam(
                ':supportPin',
                $supportPin
            );

            $stmt->execute();

            return (bool)
                $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to check support pin: ' .
                $e->getMessage()
            );

            return false;
        }
    }

    public static function convertPinToUUID(
        string $supportPin
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE support_pin = :supportPin
                   AND deleted = "false"
                 LIMIT 1'
            );

            $stmt->bindParam(
                ':supportPin',
                $supportPin
            );

            $stmt->execute();

            return $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to convert pin to uuid: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    /**
     * MySQL-safe email -> UUID lookup.
     */
    public static function convertEmailToUUID(
        string $email
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE email = :email
                   AND deleted = :deleted
                 LIMIT 1'
            );

            $stmt->execute([
                ':email' => $email,
                ':deleted' => 'false',
            ]);

            return $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to convert email to uuid: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getInfo(
        string $token,
        UserColumns|string $info,
        bool $encrypted
    ): ?string {
        try {
            if (
                !in_array(
                    $info,
                    UserColumns::getColumns()
                )
            ) {
                throw new \InvalidArgumentException(
                    'Invalid column name: ' .
                    $info
                );
            }

            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT ' .
                $info .
                '
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE token = :token'
            );

            $stmt->bindParam(':token', $token);
            $stmt->execute();

            if ($encrypted) {
                return
                    App::getInstance(true)
                        ->decrypt(
                            $stmt->fetchColumn()
                        )
                    ?? null;
            }

            return
                $stmt->fetchColumn()
                ?? null;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to grab the info about the user: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getInfoUUID(
        string $uuid,
        UserColumns|string $info,
        bool $encrypted
    ): ?string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT ' .
                $info .
                '
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE uuid = :uuid'
            );

            $stmt->bindParam(':uuid', $uuid);
            $stmt->execute();

            if ($encrypted) {
                return
                    App::getInstance(true)
                        ->decrypt(
                            $stmt->fetchColumn()
                        )
                    ?? null;
            }

            return
                $stmt->fetchColumn()
                ?? null;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get info: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getInfoArray(
        string $token,
        array $columns,
        array $columns_encrypted
    ): array {
        try {
            $con = self::getPdoConnection();

            $columns_str =
                implode(', ', $columns);

            $stmt = $con->prepare(
                'SELECT ' .
                $columns_str .
                '
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE token = :token'
            );

            $stmt->bindParam(':token', $token);
            $stmt->execute();

            $result =
                $stmt->fetch(\PDO::FETCH_ASSOC);

            if (!$result) {
                return [];
            }

            foreach ($columns as $column) {
                if (
                    in_array(
                        $column,
                        $columns_encrypted
                    )
                ) {
                    if (
                        isset($result[$column]) &&
                        $result[$column] !== null
                    ) {
                        $result[$column] =
                            App::getInstance(true)
                                ->decrypt(
                                    $result[$column]
                                );
                    }
                }
            }

            return $result;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get info: ' .
                $e->getMessage()
            );

            return [];
        }
    }

    public static function updateInfo(
        string $token,
        UserColumns|string $info,
        ?string $value,
        bool $encrypted
    ): bool {
        try {
            if (
                !in_array(
                    $info,
                    UserColumns::getColumns()
                )
            ) {
                throw new \InvalidArgumentException(
                    'Invalid column name: ' .
                    $info
                );
            }

            $con = self::getPdoConnection();

            if ($encrypted) {
                $value =
                    App::getInstance(true)
                        ->encrypt($value);
            }

            $stmt = $con->prepare(
                'UPDATE ' .
                self::TABLE_NAME .
                '
                 SET ' .
                $info .
                ' = :value
                 WHERE token = :token'
            );

            $stmt->bindParam(
                ':value',
                $value
            );

            $stmt->bindParam(
                ':token',
                $token
            );

            return $stmt->execute();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to update user info: ' .
                $e->getMessage()
            );

            return false;
        }
    }

    public static function getTokenFromUUID(
        string $uuid
    ): ?string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT token
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE uuid = :uuid'
            );

            $stmt->bindParam(':uuid', $uuid);
            $stmt->execute();

            return
                $stmt->fetchColumn()
                ?? null;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to uuid to token: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getUUIDFromInfo(
        UserColumns|string $info,
        string $value
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE ' .
                $info .
                ' = :value'
            );

            $stmt->bindParam(':value', $value);
            $stmt->execute();

            return $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to uuid from info: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getUUIDFromGitHubID(
        string $githubID
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE github_id = :githubID
                   AND deleted = "false"
                 LIMIT 1'
            );

            $stmt->bindParam(
                ':githubID',
                $githubID
            );

            $stmt->execute();

            return $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to uuid from github id: ' .
                $e->getMessage()
            );

            return '';
        }
    }

    public static function getUUIDFromDiscordID(
        string $discordID
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE discord_id = :discordID
                   AND deleted = "false"
                 LIMIT 1'
            );

            $stmt->bindParam(
                ':discordID',
                $discordID
            );

            $stmt->execute();

            return $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to uuid from discord id: ' .
                $e->getMessage()
            );

            return '';
        }
    }

    public static function getTokenFromEmail(
        string $email
    ): string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT token
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE email = :email'
            );

            $stmt->bindParam(':email', $email);
            $stmt->execute();

            return $stmt->fetchColumn();
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to uuid to token: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function processTemplate(
        string $template,
        string $uuid
    ): string {
        try {
            $columns = [
                UserColumns::USERNAME,
                UserColumns::EMAIL,
                UserColumns::FIRST_NAME,
                UserColumns::LAST_NAME,
                UserColumns::AVATAR,
                UserColumns::BACKGROUND,
                UserColumns::ROLE_ID,
                UserColumns::FIRST_IP,
                UserColumns::LAST_IP,
                UserColumns::BANNED,
                UserColumns::VERIFIED,
                UserColumns::TWO_FA_ENABLED,
                UserColumns::DELETED,
                UserColumns::LAST_SEEN,
                UserColumns::FIRST_SEEN,
            ];

            $columns_encrypted = [
                UserColumns::FIRST_NAME,
                UserColumns::LAST_NAME,
            ];

            $userInfo =
                self::getInfoArray(
                    self::getTokenFromUUID($uuid),
                    $columns,
                    $columns_encrypted
                );

            foreach (
                $userInfo
                as $key => $value
            ) {
                $template =
                    str_replace(
                        '${' . $key . '}',
                        $value,
                        $template
                    );
            }

            return $template;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to process the template: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function delete(
        string $token
    ): bool {
        return self::updateInfo(
            $token,
            UserColumns::DELETED,
            'true',
            false
        );
    }

    public static function getCredits(
        string $token
    ): int {
        return intval(
            self::getInfo(
                $token,
                UserColumns::CREDITS,
                false
            )
        );
    }

    public static function addCredits(
        string $token,
        int $credits
    ): void {
        $currentCredits =
            self::getCredits($token);

        self::updateInfo(
            $token,
            UserColumns::CREDITS,
            $currentCredits + $credits,
            false
        );
    }

    public static function removeCredits(
        string $token,
        int $credits
    ): void {
        $currentCredits =
            self::getCredits($token);

        self::updateInfo(
            $token,
            UserColumns::CREDITS,
            $currentCredits - $credits,
            false
        );
    }

    public static function removeCreditsAtomic(
        string $token,
        int $credits
    ): bool {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT credits
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE token = ?'
            );

            $stmt->execute([$token]);

            $currentCredits =
                (int) $stmt->fetchColumn();

            if ($currentCredits < $credits) {
                return false;
            }

            $stmt = $con->prepare(
                'UPDATE ' .
                self::TABLE_NAME .
                '
                 SET credits = credits - ?
                 WHERE token = ?
                   AND credits >= ?'
            );

            $result = $stmt->execute([
                $credits,
                $token,
                $credits,
            ]);

            return
                $result &&
                $stmt->rowCount() > 0;
        } catch (\Exception $e) {
            self::db_Error(
                'Failed to remove credits atomically: ' .
                $e->getMessage()
            );

            return false;
        }
    }

    public static function addCreditsAtomic(
        string $token,
        int $credits
    ): bool {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'UPDATE ' .
                self::TABLE_NAME .
                '
                 SET credits = credits + ?
                 WHERE token = ?'
            );

            $result = $stmt->execute([
                $credits,
                $token,
            ]);

            return
                $result &&
                $stmt->rowCount() > 0;
        } catch (\Exception $e) {
            self::db_Error(
                'Failed to add credits atomically: ' .
                $e->getMessage()
            );

            return false;
        }
    }

    public static function checkCreditsAtomic(
        string $token,
        int $requiredCredits
    ): array {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT credits
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE token = ?'
            );

            $stmt->execute([$token]);

            $currentCredits =
                (int) $stmt->fetchColumn();

            return [
                'has_sufficient' =>
                    $currentCredits >=
                    $requiredCredits,
                'current_credits' =>
                    $currentCredits,
            ];
        } catch (\Exception $e) {
            self::db_Error(
                'Failed to check credits atomically: ' .
                $e->getMessage()
            );

            return [
                'has_sufficient' => false,
                'current_credits' => 0,
            ];
        }
    }

    public static function getUserByUploadKey(
        string $uploadKey
    ): ?string {
        try {
            $con = self::getPdoConnection();

            $stmt = $con->prepare(
                'SELECT uuid
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE image_hosting_upload_key =
                       :uploadKey'
            );

            $stmt->bindParam(
                ':uploadKey',
                $uploadKey
            );

            $stmt->execute();

            $result =
                $stmt->fetchColumn();

            return
                $result
                ? (string) $result
                : null;
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get user by upload key: ' .
                $e->getMessage()
            );

            return null;
        }
    }

    public static function getPaginatedWithSearch(
        array $rows,
        array $encrypted,
        int $page = 1,
        int $limit = 20,
        ?string $search = null
    ): array {
        try {
            $page = max(1, $page);

            $limit =
                max(
                    1,
                    min(100, $limit)
                );

            $offset =
                ($page - 1) * $limit;

            $con = self::getPdoConnection();

            $where =
                'deleted = "false"';

            $params = [];

            if (
                $search !== null &&
                $search !== ''
            ) {
                $where .=
                    ' AND
                     (
                         username LIKE :q
                         OR email LIKE :q
                     )';

                $params[':q'] =
                    '%' . $search . '%';
            }

            $countSql =
                'SELECT COUNT(*) AS cnt
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE ' .
                $where;

            $countStmt =
                $con->prepare($countSql);

            foreach (
                $params
                as $k => $v
            ) {
                $countStmt->bindValue(
                    $k,
                    $v
                );
            }

            $countStmt->execute();

            $total =
                (int)
                $countStmt
                    ->fetch(\PDO::FETCH_ASSOC)['cnt'];

            $sql =
                'SELECT ' .
                implode(', ', $rows) .
                '
                 FROM ' .
                self::TABLE_NAME .
                '
                 WHERE ' .
                $where .
                '
                 ORDER BY id ASC
                 LIMIT :limit
                 OFFSET :offset';

            $stmt =
                $con->prepare($sql);

            foreach (
                $params
                as $k => $v
            ) {
                $stmt->bindValue(
                    $k,
                    $v
                );
            }

            $stmt->bindValue(
                ':limit',
                $limit,
                \PDO::PARAM_INT
            );

            $stmt->bindValue(
                ':offset',
                $offset,
                \PDO::PARAM_INT
            );

            $stmt->execute();

            $users =
                $stmt->fetchAll(
                    \PDO::FETCH_ASSOC
                );

            foreach ($users as &$user) {
                foreach ($rows as $row) {
                    if (
                        in_array(
                            $row,
                            $encrypted
                        )
                    ) {
                        $user[$row] =
                            App::getInstance(true)
                                ->decrypt(
                                    $user[$row]
                                );
                    }
                }
            }

            return [
                'items' => $users,
                'total' => $total,
            ];
        } catch (\Exception $e) {
            Database::db_Error(
                'Failed to get paginated user list: ' .
                $e->getMessage()
            );

            return [
                'items' => [],
                'total' => 0,
            ];
        }
    }
}
