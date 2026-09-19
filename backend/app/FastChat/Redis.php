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

namespace MythicalDash\FastChat;

use Predis\Client;
use MythicalDash\App;

class Redis
{
    private $redis;

    public function __construct()
    {
        $app = App::getInstance(true);
        $app->loadEnv();

        if (
            isset($_ENV['REDIS_HOST']) &&
            isset($_ENV['REDIS_PORT']) &&
            isset($_ENV['REDIS_USER']) &&
            isset($_ENV['REDIS_PASSWORD'])
        ) {
            $host = $_ENV['REDIS_HOST'];
            $port = (int) $_ENV['REDIS_PORT'];
            $username = $_ENV['REDIS_USER'];
            $password = $_ENV['REDIS_PASSWORD'];

            $tlsEnabled = filter_var(
                $_ENV['REDIS_TLS'] ?? true,
                FILTER_VALIDATE_BOOLEAN
            );

            $connection = [
                'scheme' => $tlsEnabled ? 'tls' : 'tcp',
                'host' => $host,
                'port' => $port,
                'username' => $username,
                'password' => $password,
                'timeout' => 5.0,
            ];

            if ($tlsEnabled) {
                $connection['ssl'] = [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                ];
            }

            $this->redis = new Client($connection);
        } else {
            $app->getLogger()->error(
                'Valkey connection failed: missing required environment variables'
            );
        }
    }

    public function getRedis(): Client
    {
        return $this->redis;
    }

    public function testConnection(): bool
    {
        try {
            $redis = $this->getRedis();
            $redis->connect();

            return $redis->isConnected();
        } catch (\Exception $e) {
            App::getInstance(true)->getLogger()->error(
                'Failed to connect to Valkey: ' . $e->getMessage()
            );

            return false;
        }
    }
}
