// Docker status for every Auto-validate option (templates/partials/hunt_options.html: Hunt, Analyse, Manual)
document.addEventListener('DOMContentLoaded', async function() {
    const labels = Array.from(document.querySelectorAll('.auto-validate-label'));
    if (!labels.length) return;
    let state;
    try {
        const data = await (await fetch('/api/validation/docker-status')).json();
        state = data.available
            ? { text: 'Docker Ready', bg: 'rgba(16, 185, 129, 0.15)', fg: '#059669', ok: true }
            : { text: 'Docker Required', bg: 'rgba(245, 158, 11, 0.15)', fg: '#d97706', ok: false,
                hint: data.message || 'Docker is required for validation' };
    } catch (error) {
        console.error('Failed to check Docker status:', error);
        state = { text: 'Status Unknown', bg: 'rgba(107, 114, 128, 0.15)', fg: '#6b7280', ok: false };
    }
    labels.forEach(function (label) {
        const checkbox = label.querySelector('input[type="checkbox"]');
        const badge = label.querySelector('.docker-status-badge');
        const hint = label.querySelector('.option-hint');
        if (badge) {
            badge.textContent = state.text;
            badge.style.display = 'inline';
            badge.style.background = state.bg;
            badge.style.color = state.fg;
        }
        checkbox.disabled = !state.ok;
        if (!state.ok) checkbox.checked = false;
        if (state.hint && hint) hint.textContent = state.hint;
        if (state.hint) label.style.opacity = '0.6';
    });
});
