import router from '@/router';
import Swal from 'sweetalert2';

interface SessionResponse {
    success: boolean;
    error_code?: string;
    user_info: Record<string, unknown>;
    billing: Record<string, unknown>;
    stats: Record<string, unknown>;
    permissions?: string[];
}

class Session {
    private static sessionData: Record<string, unknown> = {};
    private static updateInterval: number | null = null;
    private static permissions: string[] = [];
    private static initPromise: Promise<void> | null = null;
    private static retryCount = 0;
    private static maxRetries = 3;
    private static retryDelay = 2000;
    private static isRefreshing = false;

    static isSessionValid(): boolean {
        return document.cookie.split(';').some((cookie) => cookie.trim().startsWith('user_token='));
    }

    static getInfo(key: string): string {
        if (this.sessionData[key] !== undefined) {
            return this.sessionData[key] as string;
        }

        const item = localStorage.getItem(key);

        if (item) {
            try {
                const value = JSON.parse(item);
                this.sessionData[key] = value;
                return value;
            } catch {
                return item;
            }
        }

        return '';
    }

    static getInfoInt(key: string): number {
        return parseInt(this.getInfo(key)) || 0;
    }

    private static async fetchSessionData(retry = true): Promise<SessionResponse> {
        try {
            const response = await fetch('/api/user/session', {
                headers: {
                    'Cache-Control': 'no-cache',
                    Pragma: 'no-cache',
                },
            });

            if (!response.ok) {
                let errorData: SessionResponse = {
                    success: false,
                    error_code: response.status === 503 ? 'SERVER_UNAVAILABLE' : 'SERVER_ERROR',
                    user_info: {},
                    billing: {},
                    stats: {},
                };

                try {
                    const parsed = await response.json();

                    errorData = {
                        ...errorData,
                        ...parsed,
                    };
                } catch {
                    // Response was not JSON.
                }

                console.error(`Server responded with status ${response.status}: ${response.statusText}`);

                if (errorData.error_code === 'TWO_FA_BLOCKED') {
                    await this.handleSessionError(errorData);
                    throw new Error('TWO_FA_BLOCKED');
                }

                if (this.isSessionValid()) {
                    await this.handleSessionError(errorData);
                }

                throw new Error(`Server responded with status ${response.status}`);
            }

            const data = await response.json();

            if (!data.success && this.isSessionValid()) {
                await this.handleSessionError(data);
            }

            this.retryCount = 0;

            return data;
        } catch (error) {
            console.error('Error fetching session data:', error);

            if (
                error instanceof Error &&
                (
                    error.message.includes('TWO_FA_BLOCKED') ||
                    error.message.includes('401') ||
                    error.message.includes('403') ||
                    error.message.includes('503') ||
                    error.message.includes('SERVER_UNAVAILABLE')
                )
            ) {
                throw error;
            }

            if (retry && this.retryCount < this.maxRetries) {
                this.retryCount++;

                console.log(`Retrying session fetch (${this.retryCount}/${this.maxRetries})...`);

                return new Promise((resolve, reject) => {
                    setTimeout(async () => {
                        try {
                            const result = await this.fetchSessionData(true);
                            resolve(result);
                        } catch (retryError) {
                            console.error('Retry failed:', retryError);
                            reject(retryError);
                        }
                    }, this.retryDelay);
                });
            }

            if (this.isSessionValid()) {
                await this.handleSessionError({
                    success: false,
                    error_code: 'SERVER_ERROR',
                    user_info: {},
                    billing: {},
                    stats: {},
                });
            }

            throw error;
        }
    }

    private static async handleSessionError(data: SessionResponse): Promise<void> {
        /*
         * IMPORTANT:
         * A 2FA challenge does NOT mean the session is invalid.
         * Keep the user_token cookie because the 2FA verification
         * endpoint needs it.
         */
        if (data.error_code === 'TWO_FA_BLOCKED') {
            this.cleanup();

            await router.push('/auth/2fa/verify');

            return;
        }

        document.cookie = 'user_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';

        document.cookie =
            'user_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=' +
            window.location.hostname;

        document.cookie =
            'user_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.' +
            window.location.hostname;

        localStorage.clear();

        this.sessionData = {};

        this.cleanup();

        if (data.error_code === 'SERVER_UNAVAILABLE') {
            await Swal.fire({
                title: 'Server Unavailable',
                text: 'The server is currently unavailable. Please try again later.',
                icon: 'error',
                confirmButtonText: 'OK',
            });

            router.push('/auth/login');
        } else {
            await Swal.fire({
                title: 'Session Error',
                text: 'Your session has expired or is invalid.',
                footer: 'Please log in again.',
                icon: 'error',
                confirmButtonText: 'OK',
            });

            router.push('/auth/login');
        }
    }

    private static updateSessionStorage(data: SessionResponse): void {
        if (!data || !data.success) {
            return;
        }

        const {
            user_info,
            billing,
            stats,
            permissions,
        } = data;

        if (permissions && Array.isArray(permissions)) {
            this.permissions = permissions;

            localStorage.setItem(
                'user_permissions',
                JSON.stringify(permissions),
            );
        }

        this.sessionData = {
            ...this.sessionData,
            ...(stats || {}),
        };

        try {
            if (user_info && typeof user_info === 'object') {
                Object.entries(user_info).forEach(([key, value]) => {
                    if (value !== null && value !== undefined) {
                        localStorage.setItem(
                            key,
                            JSON.stringify(value),
                        );
                    }
                });
            }

            if (billing && typeof billing === 'object') {
                Object.entries(billing).forEach(([key, value]) => {
                    if (value !== null && value !== undefined) {
                        localStorage.setItem(
                            key,
                            JSON.stringify(value),
                        );
                    }
                });
            }

            if (stats && typeof stats === 'object') {
                Object.entries(stats).forEach(([key, value]) => {
                    if (value !== null && value !== undefined) {
                        localStorage.setItem(
                            key,
                            JSON.stringify(value),
                        );
                    }
                });
            }
        } catch (error) {
            console.error(
                'Error updating session storage:',
                error,
            );
        }
    }

    private static async ensureInitialized(): Promise<void> {
        if (!this.initPromise) {
            this.initPromise = this.initialize();
        }

        return this.initPromise;
    }

    private static async initialize(): Promise<void> {
        try {
            if (!this.isSessionValid()) {
                throw new Error('No valid session found');
            }

            const cachedPermissions =
                localStorage.getItem('user_permissions');

            if (cachedPermissions) {
                try {
                    this.permissions =
                        JSON.parse(cachedPermissions);
                } catch (e) {
                    console.error(
                        'Failed to parse cached permissions:',
                        e,
                    );
                }
            }

            const data =
                await this.fetchSessionData();

            if (data.success) {
                this.updateSessionStorage(data);
            }
        } catch (error) {
            console.error(
                'Error initializing session:',
                error,
            );

            this.initPromise = null;

            throw error;
        }
    }

    static hasPermission(node: string): boolean {
        if (this.permissions.includes('admin.root')) {
            return true;
        }

        return this.permissions.includes(node);
    }

    static getPermissions(): string[] {
        if (this.permissions.includes('admin.root')) {
            return [
                '*',
                ...this.permissions,
            ];
        }

        return [
            ...this.permissions,
        ];
    }

    static async refreshSession(): Promise<boolean> {
        if (this.isRefreshing) {
            return false;
        }

        try {
            this.isRefreshing = true;

            if (!this.isSessionValid()) {
                return false;
            }

            const data =
                await this.fetchSessionData(false);

            if (data.success) {
                this.updateSessionStorage(data);

                return true;
            }

            return false;
        } catch (error) {
            console.error(
                'Error refreshing session:',
                error,
            );

            return false;
        } finally {
            this.isRefreshing = false;
        }
    }

    static async startSession(): Promise<void> {
        if (this.updateInterval !== null) {
            clearInterval(this.updateInterval);

            this.updateInterval = null;
        }

        if (!this.isSessionValid()) {
            console.warn(
                'Cannot start session: No valid session token',
            );

            return;
        }

        try {
            await this.ensureInitialized();

            this.updateInterval =
                window.setInterval(async () => {
                    if (!this.isSessionValid()) {
                        this.cleanup();

                        return;
                    }

                    try {
                        await this.refreshSession();
                    } catch (error) {
                        console.error(
                            'Error updating session:',
                            error,
                        );

                        if (
                            error instanceof Error &&
                            (
                                error.message.includes('503') ||
                                error.message.includes('SERVER_UNAVAILABLE') ||
                                error.message.includes('SERVER_ERROR')
                            )
                        ) {
                            console.error(
                                'Server unavailable, stopping session refresh',
                            );

                            this.cleanup();
                        }
                    }
                }, 60000);
        } catch (error) {
            console.error(
                'Failed to start session:',
                error,
            );

            this.cleanup();

            if (
                this.isSessionValid() &&
                !(
                    error instanceof Error &&
                    error.message.includes('TWO_FA_BLOCKED')
                )
            ) {
                await Swal.fire({
                    title: 'Error',
                    text: 'Failed to start session. Please try again.',
                    icon: 'error',
                    confirmButtonText: 'OK',
                });

                router.push('/auth/login');
            }
        }
    }

    static cleanup(): void {
        if (this.updateInterval !== null) {
            clearInterval(this.updateInterval);

            this.updateInterval = null;
        }

        this.retryCount = 0;
        this.sessionData = {};
        this.permissions = [];
        this.initPromise = null;

        localStorage.removeItem('user_permissions');

        this.isRefreshing = false;
    }

    static hasOrRedirectToErrorPage(node: string): boolean {
        if (this.permissions.length === 0) {
            const cachedPermissions =
                localStorage.getItem('user_permissions');

            if (cachedPermissions) {
                try {
                    this.permissions =
                        JSON.parse(cachedPermissions);
                } catch (e) {
                    console.error(
                        'Failed to parse cached permissions:',
                        e,
                    );
                }
            }
        }

        if (this.hasPermission(node)) {
            console.log(
                'User has permission to access this resource',
            );

            return true;
        }

        console.log(
            'User does not have permission to access this resource',
        );

        Swal.fire({
            title: 'Access Denied',
            text: 'You do not have permission to access this resource.',
            icon: 'error',
            confirmButtonText: 'OK',
        }).then(() => {
            router.push('/errors/403');
        });

        return false;
    }

    static Permission = class {
        static HasOrRedirectToErrorPage(
            node: string,
        ): boolean {
            return Session.hasOrRedirectToErrorPage(
                node,
            );
        }

        static Has(node: string): boolean {
            return Session.hasPermission(node);
        }

        static GetAll(): string[] {
            return Session.getPermissions();
        }
    };
}

export default Session;
