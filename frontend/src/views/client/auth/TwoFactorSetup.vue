<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import Layout from '@/components/client/Layout.vue';
import FormCard from '@/components/client/Auth/FormCard.vue';
import FormInput from '@/components/client/Auth/FormInput.vue';
import { useI18n } from 'vue-i18n';
import { useSound } from '@vueuse/sound';
import failedAlertSfx from '@/assets/sounds/error.mp3';
import successAlertSfx from '@/assets/sounds/success.mp3';
import Swal from 'sweetalert2';
import Turnstile from 'vue-turnstile';
import { useSettingsStore } from '@/stores/settings';
import { useRouter } from 'vue-router';
import VueQrcode from 'vue-qrcode';
import Session from '@/mythicaldash/Session';
import Auth from '@/mythicaldash/Auth';
import { MythicalDOM } from '@/mythicaldash/MythicalDOM';

const Settings = useSettingsStore();

const { play: playError } = useSound(failedAlertSfx);
const { play: playSuccess } = useSound(successAlertSfx);

const router = useRouter();
const { t } = useI18n();

const loading = ref(false);
const ready = ref(false);

const form = reactive({
    secret: '',
    code: '',
    turnstileResponse: '',
});

const turnstileKey = ref(0);

MythicalDOM.setPageTitle(
    t('auth.pages.twofactor_setup.page.title'),
);

const fetchSecret = async () => {
    try {
        loading.value = true;

        const data = await Auth.getTwoFactorSecret();

        if (!data.success || !data.secret) {
            throw new Error(
                data.message ||
                    'Failed to get two-factor secret',
            );
        }

        /*
         * The backend now reuses the same secret if this page is refreshed,
         * so scanning this QR remains valid until setup is completed.
         */
        form.secret = data.secret;
        ready.value = true;
    } catch (error) {
        console.error(
            'Error fetching 2FA secret:',
            error,
        );

        playError();

        await Swal.fire({
            icon: 'error',
            title: '2FA Setup Error',
            text: 'XalixCloud could not start two-factor setup.',
        });

        router.push('/account');
    } finally {
        loading.value = false;
    }
};

const handleSubmit = async () => {
    const code = form.code.replace(/\D/g, '');

    if (code.length !== 6) {
        playError();

        Swal.fire({
            icon: 'error',
            title:
                t(
                    'auth.pages.twofactor_setup.alerts.missing_fields.title',
                ),
            text: 'Enter the 6-digit code from your authenticator app.',
        });

        return;
    }

    try {
        loading.value = true;

        const response =
            await Auth.verifyTwoFactor(
                code,
                form.turnstileResponse,
            );

        if (!response.success) {
            playError();

            Swal.fire({
                icon: 'error',
                title:
                    t(
                        'auth.pages.twofactor_setup.alerts.error.title',
                    ),
                text:
                    response.error_code === 'INVALID_CODE'
                        ? 'That authenticator code is not valid. Wait for a new code and try again.'
                        : response.message ||
                          'Two-factor verification failed.',
            });

            return;
        }

        localStorage.setItem(
            '2fa_enabled',
            JSON.stringify('true'),
        );

        localStorage.setItem(
            '2fa_blocked',
            JSON.stringify('false'),
        );

        await Session.refreshSession();

        playSuccess();

        await Swal.fire({
            icon: 'success',
            title:
                t(
                    'auth.pages.twofactor_setup.alerts.success.title',
                ),
            text: 'Two-factor authentication is now enabled on your XalixCloud account.',
        });

        router.push('/account');
    } catch (error) {
        playError();

        console.error(
            'Error verifying 2FA code:',
            error,
        );

        Swal.fire({
            icon: 'error',
            title: '2FA Setup Error',
            text: 'Two-factor verification failed.',
        });
    } finally {
        loading.value = false;
        turnstileKey.value++;
    }
};

onMounted(async () => {
    if (!Session.isSessionValid()) {
        await router.push('/auth/login');
        return;
    }

    /*
     * Get fresh account state instead of trusting stale localStorage.
     */
    await Session.refreshSession();

    if (
        Session.getInfo(
            '2fa_enabled',
        ) === 'true'
    ) {
        await router.push('/account');
        return;
    }

    await fetchSecret();
});
</script>

<template>
    <Layout>
        <FormCard
            :title="t('auth.pages.twofactor_setup.page.subTitle')"
            @submit="handleSubmit"
        >
            <div
                v-if="ready"
                style="
                    display: flex;
                    justify-content: center;
                    margin-bottom: 20px;
                "
            >
                <vue-qrcode
                    :value="`otpauth://totp/XalixCloud:${encodeURIComponent(
                        Session.getInfo('email') || 'account',
                    )}?secret=${form.secret}&issuer=${encodeURIComponent(
                        Settings.getSetting('app_name') || 'XalixCloud',
                    )}`"
                    type="image/png"
                    :color="{
                        dark: '#000000',
                        light: '#ffffff',
                    }"
                />
            </div>

            <FormInput
                id="secret"
                :label="
                    $t(
                        'auth.pages.twofactor_setup.page.form.secret.label',
                    )
                "
                v-model="form.secret"
                type="text"
                :placeholder="
                    t(
                        'auth.pages.twofactor_setup.page.form.secret.placeholder',
                    )
                "
                locked
            />

            <FormInput
                id="code"
                :label="
                    $t(
                        'auth.pages.twofactor_setup.page.form.code.label',
                    )
                "
                v-model="form.code"
                type="text"
                placeholder="123456"
                required
                :maxChar="6"
            />

            <button
                type="submit"
                class="w-full mt-6 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
                :disabled="loading || !ready"
            >
                {{
                    loading
                        ? t(
                              'auth.pages.twofactor_setup.page.form.setup_button.loading',
                          )
                        : t(
                              'auth.pages.twofactor_setup.page.form.setup_button.label',
                          )
                }}
            </button>

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
        </FormCard>
    </Layout>
</template>
