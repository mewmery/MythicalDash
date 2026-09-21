<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import Layout from '@/components/client/Layout.vue';
import FormCard from '@/components/client/Auth/FormCard.vue';
import FormInput from '@/components/client/Auth/FormInput.vue';
import Swal from 'sweetalert2';
import { useRouter } from 'vue-router';
import Turnstile from 'vue-turnstile';
import { useSettingsStore } from '@/stores/settings';

const Settings = useSettingsStore();

import { useSound } from '@vueuse/sound';
import failedAlertSfx from '@/assets/sounds/error.mp3';
import successAlertSfx from '@/assets/sounds/success.mp3';
import Auth from '@/mythicaldash/Auth';
import { useI18n } from 'vue-i18n';
import { MythicalDOM } from '@/mythicaldash/MythicalDOM';

const { t } = useI18n();

const { play: playError } =
    useSound(failedAlertSfx);

const { play: playSuccess } =
    useSound(successAlertSfx);

const router = useRouter();

/*
 * Login page intentionally clears cached session info.
 * The backend cookie is created again after a successful login.
 */
localStorage.clear();
sessionStorage.clear();

MythicalDOM.setPageTitle(
    t('auth.pages.login.page.title')
);

const loading = ref(false);

const form = reactive({
    email: '',
    password: '',
    turnstileResponse: '',
});

const turnstileKey = ref(0);

const domainName =
    localStorage.getItem('domain_name');

interface AltAccount {
    uuid: string;
    username: string;
    avatar: string;
}

const errorMessages = {
    TURNSTILE_FAILED:
        t(
            'auth.pages.login.alerts.error.cloudflare_error'
        ),

    INVALID_CREDENTIALS:
        t(
            'auth.pages.login.alerts.error.invalid_credentials'
        ),

    ACCOUNT_NOT_VERIFIED:
        t(
            'auth.pages.login.alerts.error.not_verified'
        ),

    ACCOUNT_BANNED:
        t(
            'auth.pages.login.alerts.error.banned'
        ),

    ACCOUNT_DELETED:
        t(
            'auth.pages.login.alerts.error.deleted'
        ),

    PTERODACTYL_USER_NOT_FOUND:
        t(
            'auth.pages.login.alerts.error.pterodactyl_user_not_found'
        ),

    PTERODACTYL_ERROR:
        t(
            'auth.pages.login.alerts.error.pterodactyl_error'
        ),

    PTERODACTYL_NOT_ENABLED:
        t(
            'auth.pages.login.alerts.error.pterodactyl_not_enabled'
        ),

    PROXY_DETECTED:
        t(
            'auth.pages.login.alerts.error.proxy_detected'
        ),

    MULTIPLE_ACCOUNTS:
        t(
            'auth.pages.login.alerts.error.multiple_accounts'
        ),

    DISCORD_NOT_ENABLED:
        t(
            'auth.pages.login.alerts.error.discord_not_enabled'
        ),

    GITHUB_NOT_ENABLED:
        t(
            'auth.pages.login.alerts.error.github_not_enabled'
        ),

    DISCORD_TOKEN_FAILED:
        t(
            'auth.pages.login.alerts.error.discord_token_failed'
        ),

    GITHUB_TOKEN_FAILED:
        t(
            'auth.pages.login.alerts.error.github_token_failed'
        ),

    DISCORD_USER_FAILED:
        t(
            'auth.pages.login.alerts.error.discord_user_failed'
        ),

    GITHUB_USER_FAILED:
        t(
            'auth.pages.login.alerts.error.github_user_failed'
        ),

    DISCORD_USER_NOT_FOUND:
        t(
            'auth.pages.login.alerts.error.discord_user_not_found'
        ),

    GITHUB_USER_NOT_FOUND:
        t(
            'auth.pages.login.alerts.error.github_user_not_found'
        ),

    DISCORD_USER_MISMATCH:
        t(
            'auth.pages.login.alerts.error.discord_user_mismatch'
        ),

    GITHUB_USER_MISMATCH:
        t(
            'auth.pages.login.alerts.error.github_user_mismatch'
        ),

    DISCORD_ALREADY_LINKED:
        t(
            'auth.pages.login.alerts.error.discord_already_linked'
        ),

    GITHUB_ALREADY_LINKED:
        t(
            'auth.pages.login.alerts.error.github_already_linked'
        ),

    DISCORD_NOT_LINKED:
        t(
            'auth.pages.login.alerts.error.discord_not_linked'
        ),

    GITHUB_NOT_LINKED:
        t(
            'auth.pages.login.alerts.error.github_not_linked'
        ),

    DISCORD_AUTH_FAILED:
        t(
            'auth.pages.login.alerts.error.discord_auth_failed'
        ),

    GITHUB_AUTH_FAILED:
        t(
            'auth.pages.login.alerts.error.github_auth_failed'
        ),
};

const handleSubmit = async () => {
    try {
        loading.value = true;

        const response =
            await Auth.login(
                form.email,
                form.password,
                form.turnstileResponse,
            );

        /*
         * Password was correct, but XalixCloud requires
         * the authenticator code before entering the panel.
         */
        if (
            response.success === true &&
            response.requires_2fa === true
        ) {
            loading.value = false;

            await router.push(
                '/auth/2fa/verify'
            );

            return;
        }

        if (!response.success) {
            const error_code =
                response.error_code as keyof typeof errorMessages;

            if (
                errorMessages[
                    error_code
                ]
            ) {
                playError();

                if (
                    error_code ===
                        'MULTIPLE_ACCOUNTS' &&
                    response.info &&
                    response.info.length > 0
                ) {
                    const altAccounts =
                        response.info
                            .map(
                                (
                                    account: AltAccount,
                                ) => `
                                    <div class="flex items-center space-x-3 mb-2">
                                        <img
                                            src="${account.avatar}"
                                            alt="${account.username}"
                                            class="w-8 h-8 rounded-full"
                                        >
                                        <div>
                                            <div class="font-medium text-white">
                                                ${account.username}
                                            </div>
                                            <div class="text-sm text-gray-400">
                                                ${account.uuid}
                                            </div>
                                        </div>
                                    </div>
                                `,
                            )
                            .join('');

                    Swal.fire({
                        icon: 'error',

                        title:
                            t(
                                'auth.pages.login.alerts.error.title'
                            ),

                        html: `
                            <div class="text-left">
                                <p class="mb-4">
                                    ${errorMessages[error_code]}
                                </p>

                                <div class="bg-gray-800 p-4 rounded-lg">
                                    <h3 class="text-lg font-medium mb-2">
                                        Detected Alt Accounts:
                                    </h3>

                                    ${altAccounts}
                                </div>
                            </div>
                        `,

                        footer:
                            t(
                                'auth.pages.login.alerts.error.footer'
                            ),

                        showConfirmButton:
                            true,
                    });
                } else {
                    Swal.fire({
                        icon: 'error',

                        title:
                            t(
                                'auth.pages.login.alerts.error.title'
                            ),

                        text:
                            errorMessages[
                                error_code
                            ],

                        footer:
                            t(
                                'auth.pages.login.alerts.error.footer'
                            ),

                        showConfirmButton:
                            true,
                    });
                }

                loading.value = false;

                return;
            }

            playError();

            Swal.fire({
                icon: 'error',

                title:
                    t(
                        'auth.pages.login.alerts.error.title'
                    ),

                text:
                    response.message,

                footer:
                    t(
                        'auth.pages.login.alerts.error.footer'
                    ),

                showConfirmButton:
                    true,
            });

            loading.value = false;

            return;
        }

        /*
         * No 2FA required: normal successful login.
         */
        playSuccess();

        Swal.fire({
            icon: 'success',

            title:
                t(
                    'auth.pages.login.alerts.success.title'
                ),

            text:
                t(
                    'auth.pages.login.alerts.success.login_success'
                ),

            footer:
                t(
                    'auth.pages.login.alerts.success.footer'
                ),

            showConfirmButton:
                true,
        });

        loading.value = false;

        localStorage.setItem(
            'needs_refresh',
            'true',
        );

        setTimeout(() => {
            router.push('/');
        }, 1500);
    } catch (error) {
        console.error(
            'Login failed:',
            error,
        );

        playError();

        Swal.fire({
            icon: 'error',
            title: 'Login Failed',
            text: 'An unexpected login error occurred.',
        });
    } finally {
        loading.value = false;

        turnstileKey.value++;
    }
};

function base64_decode(
    str: string | null,
): string {
    if (!str) {
        return '';
    }

    try {
        return atob(str);
    } catch (e) {
        console.error(
            'Failed to decode base64 string:',
            e,
        );

        return '';
    }
}

const handleDiscordLogin = () => {
    localStorage.setItem(
        'needs_refresh',
        'true',
    );

    setTimeout(() => {
        window.location.href =
            '/api/user/auth/callback/discord/login';
    }, 1000);
};

const handleGithubLogin = () => {
    localStorage.setItem(
        'needs_refresh',
        'true',
    );

    setTimeout(() => {
        window.location.href =
            '/api/user/auth/callback/github/login';
    }, 1000);
};

onMounted(() => {
    const urlParams =
        new URLSearchParams(
            window.location.search,
        );

    const email =
        base64_decode(
            urlParams.get('email'),
        );

    const password =
        base64_decode(
            urlParams.get('password'),
        );

    const performLogin =
        urlParams.get('performLogin');

    const error =
        urlParams.get('error');

    const message =
        urlParams.get('message');

    if (error) {
        const error_code =
            error.toUpperCase()
            as keyof typeof errorMessages;

        if (
            errorMessages[
                error_code
            ]
        ) {
            playError();

            Swal.fire({
                icon: 'error',

                title:
                    t(
                        'auth.pages.login.alerts.error.title'
                    ),

                text:
                    message
                        ? `${errorMessages[error_code]}: ${message}`
                        : errorMessages[
                              error_code
                          ],

                footer:
                    t(
                        'auth.pages.login.alerts.error.footer'
                    ),

                showConfirmButton:
                    true,
            });
        } else {
            playError();

            Swal.fire({
                icon: 'error',

                title:
                    t(
                        'auth.pages.login.alerts.error.title'
                    ),

                text:
                    message ||
                    t(
                        'auth.pages.login.alerts.error.generic'
                    ),

                footer:
                    t(
                        'auth.pages.login.alerts.error.footer'
                    ),

                showConfirmButton:
                    true,
            });
        }

        window.history.replaceState(
            {},
            '',
            window.location.pathname,
        );

        return;
    }

    if (
        email &&
        password &&
        performLogin === 'true'
    ) {
        form.email = email;
        form.password = password;

        handleSubmit();

        window.history.replaceState(
            {},
            '',
            window.location.pathname,
        );
    }
});

const isEnterpriseLogin =
    localStorage.getItem(
        'domain_name'
    ) !== null;

if (isEnterpriseLogin) {
    document.title =
        `${t(
            'auth.pages.login.page.subTitle'
        )} - ${localStorage.getItem(
            'domain_name'
        )}`;
}
</script>

<template>
    <Layout>
        <FormCard
            :title="`${$t(
                'auth.pages.login.page.subTitle',
            )}${
                domainName
                    ? ` - ${domainName}`
                    : ''
            }`"
            @submit="handleSubmit"
        >
            <FormInput
                id="email"
                :label="
                    $t(
                        'auth.pages.login.page.form.email.label',
                    )
                "
                v-model="form.email"
                :placeholder="
                    $t(
                        'auth.pages.login.page.form.email.placeholder',
                    )
                "
                required
            />

            <div
                class="flex items-center justify-between mb-2"
            >
                <label
                    class="block text-sm text-gray-400"
                >
                    {{
                        $t(
                            'auth.pages.login.page.form.password.label',
                        )
                    }}
                </label>

                <router-link
                    to="/auth/forgot-password"
                    class="text-sm text-purple-400 hover:text-purple-300"
                >
                    {{
                        $t(
                            'auth.pages.login.page.form.forgot_password',
                        )
                    }}
                </router-link>
            </div>

            <FormInput
                id="password"
                type="password"
                v-model="form.password"
                :placeholder="
                    t(
                        'auth.pages.login.page.form.password.placeholder',
                    )
                "
                required
            />

            <div
                v-if="
                    Settings.getSetting(
                        'turnstile_enabled',
                    ) === 'true'
                "
                style="
                    display: flex;
                    justify-content: center;
                    margin-top: 20px;
                "
            >
                <Turnstile
                    :key="turnstileKey"
                    :site-key="
                        Settings.getSetting(
                            'turnstile_key_pub',
                        )
                    "
                    v-model="
                        form.turnstileResponse
                    "
                />
            </div>

            <button
                type="submit"
                class="w-full mt-6 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
                :disabled="loading"
            >
                {{
                    loading
                        ? $t(
                              'auth.pages.login.page.form.login_button.loading',
                          )
                        : $t(
                              'auth.pages.login.page.form.login_button.label',
                          )
                }}
            </button>

            <div
                class="flex items-center my-4"
            >
                <div
                    class="flex-1 border-t border-gray-600"
                ></div>

                <span
                    class="px-4 text-sm text-gray-400"
                >
                    or
                </span>

                <div
                    class="flex-1 border-t border-gray-600"
                ></div>
            </div>

            <button
                v-if="
                    Settings.getSetting(
                        'discord_enabled',
                    ) === 'true'
                "
                @click="handleDiscordLogin"
                type="button"
                class="flex items-center justify-center w-full px-4 py-2 bg-[#5865F2] hover:bg-[#4752C4] text-white rounded-lg transition-colors"
            >
                Continue with Discord
            </button>

            <button
                v-if="
                    Settings.getSetting(
                        'github_enabled',
                    ) === 'true'
                "
                @click="handleGithubLogin"
                type="button"
                class="flex items-center justify-center w-full px-4 py-2 bg-[#24292e] hover:bg-[#1b1f23] text-white rounded-lg transition-colors mt-2"
            >
                Continue with GitHub
            </button>

            <p
                class="mt-4 text-center text-sm text-gray-400"
            >
                {{
                    $t(
                        'auth.pages.login.page.form.register.label',
                    )
                }}

                <router-link
                    to="/auth/register"
                    class="text-purple-400 hover:text-purple-300"
                >
                    {{
                        $t(
                            'auth.pages.login.page.form.register.link',
                        )
                    }}
                </router-link>
            </p>
        </FormCard>
    </Layout>
</template>
