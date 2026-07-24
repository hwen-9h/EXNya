// settings.js – loads and applies user settings from Supabase

const DEFAULT_SETTINGS = {
    theme: 'dark',
    currency: 'USD',
    language: 'en',
    fontSize: 14,
    emailNotifications: true,
    pushNotifications: true,
};

// ─── Apply settings to the current page ─────────────────────────────
function applySettings(settings) {
    const isDark = settings.theme === 'dark';
    document.documentElement.style.setProperty('--bg-base', isDark ? '#080b0f' : '#f5f5f5');
    document.documentElement.style.setProperty('--bg-elevated', isDark ? '#0d1117' : '#ffffff');
    document.documentElement.style.setProperty('--bg-hover', isDark ? '#161c25' : '#eef0f4');
    document.documentElement.style.setProperty('--text-primary', isDark ? '#e6e9ef' : '#1a1a1a');
    document.documentElement.style.setProperty('--text-secondary', isDark ? '#5e6a7a' : '#6b7a8a');
    document.documentElement.style.setProperty('--text-muted', isDark ? '#3a4554' : '#8a8f9a');
    document.documentElement.style.setProperty('--border-light', isDark ? '#1e2733' : '#d0d7de');
    document.documentElement.style.setProperty('--border-subtle', isDark ? '#151d27' : '#e5e9f0');

    document.documentElement.style.fontSize = settings.fontSize + 'px';

    window.__APP_CURRENCY = settings.currency;
    const symbols = { USD: '$', EUR: '€', GBP: '£', NGN: '₦' };
    window.__APP_CURRENCY_SYMBOL = symbols[settings.currency] || '$';
    window.__APP_LANGUAGE = settings.language;
    window.__APP_EMAIL_NOTIFICATIONS = settings.emailNotifications;
    window.__APP_PUSH_NOTIFICATIONS = settings.pushNotifications;

    document.dispatchEvent(new CustomEvent('settingsChanged', { detail: settings }));
}

// ─── Load settings from Supabase ─────────────────────────────────────
async function loadUserSettings() {
    const { data: { session } } = await window.supabaseClient.auth.getSession();
    if (!session) {
        applySettings(DEFAULT_SETTINGS);
        return;
    }
    const { data, error } = await window.supabaseClient
        .from('profiles')
        .select('theme, currency, language, font_size, email_notifications, push_notifications')
        .eq('id', session.user.id)
        .single();

    if (error || !data) {
        applySettings(DEFAULT_SETTINGS);
        return;
    }
    const settings = {
        theme: data.theme || 'dark',
        currency: data.currency || 'USD',
        language: data.language || 'en',
        fontSize: data.font_size || 14,
        emailNotifications: data.email_notifications !== undefined ? data.email_notifications : true,
        pushNotifications: data.push_notifications !== undefined ? data.push_notifications : true,
    };
    applySettings(settings);
    sessionStorage.setItem('userSettings', JSON.stringify(settings));
}

// ─── Update settings in Supabase ─────────────────────────────────────
async function updateUserSettings(newSettings) {
    const { data: { session } } = await window.supabaseClient.auth.getSession();
    if (!session) throw new Error('Not logged in');
    const { error } = await window.supabaseClient
        .from('profiles')
        .update({
            theme: newSettings.theme,
            currency: newSettings.currency,
            language: newSettings.language,
            font_size: newSettings.fontSize,
            email_notifications: newSettings.emailNotifications,
            push_notifications: newSettings.pushNotifications,
        })
        .eq('id', session.user.id);
    if (error) throw error;
    applySettings(newSettings);
}

// ─── Auto‑load ────────────────────────────────────────────────────────
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    loadUserSettings();
} else {
    document.addEventListener('DOMContentLoaded', loadUserSettings);
}
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) loadUserSettings();
});

// ─── Expose functions globally ──────────────────────────────────────
window.loadUserSettings = loadUserSettings;
window.updateUserSettings = updateUserSettings;
window.getSettings = () => {
    const stored = sessionStorage.getItem('userSettings');
    return stored ? JSON.parse(stored) : DEFAULT_SETTINGS;
};