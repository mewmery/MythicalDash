ALTER TABLE `mythicaldash_users`
ADD `discord_servers` JSON NOT NULL DEFAULT (JSON_ARRAY())
AFTER `discord_linked`;
