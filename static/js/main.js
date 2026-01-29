// ============================================
// EasyDiff - Main JavaScript
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all interactive components
    initFlashMessages();
    initSurveySelection();
    initItemManager();
    initCopyToClipboard();
    initConfirmDialogs();
});

// ============================================
// Toast Notifications - Auto dismiss
// ============================================

function initFlashMessages() {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) return;

    const toasts = toastContainer.querySelectorAll('.toast');
    toasts.forEach(toast => {
        // Remove toast after animation completes (2 seconds)
        setTimeout(() => {
            toast.remove();
            // Remove container if empty
            if (toastContainer.children.length === 0) {
                toastContainer.remove();
            }
        }, 2000);
    });
}

// ============================================
// Survey Selection UI
// ============================================

function initSurveySelection() {
    const surveyForm = document.getElementById('survey-form');
    if (!surveyForm) return;

    const bestButtons = document.querySelectorAll('.survey-btn-best');
    const worstButtons = document.querySelectorAll('.survey-btn-worst');
    const bestInput = document.getElementById('best-input');
    const worstInput = document.getElementById('worst-input');

    // Handle Best selection
    bestButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const itemId = this.dataset.itemId;

            // Check if this item is already selected as worst
            if (worstInput.value === itemId) {
                // Clear worst selection
                worstInput.value = '';
                worstButtons.forEach(b => b.classList.remove('selected'));
            }

            // Clear previous best selection
            bestButtons.forEach(b => b.classList.remove('selected'));

            // Set new selection
            this.classList.add('selected');
            bestInput.value = itemId;

            validateSurveyForm();
        });
    });

    // Handle Worst selection
    worstButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const itemId = this.dataset.itemId;

            // Check if this item is already selected as best
            if (bestInput.value === itemId) {
                // Clear best selection
                bestInput.value = '';
                bestButtons.forEach(b => b.classList.remove('selected'));
            }

            // Clear previous worst selection
            worstButtons.forEach(b => b.classList.remove('selected'));

            // Set new selection
            this.classList.add('selected');
            worstInput.value = itemId;

            validateSurveyForm();
        });
    });

    // Form validation
    function validateSurveyForm() {
        const submitBtn = document.getElementById('survey-submit');
        if (submitBtn) {
            const isValid = bestInput.value && worstInput.value && bestInput.value !== worstInput.value;
            submitBtn.disabled = !isValid;
        }
    }

    // Initial validation state
    validateSurveyForm();
}

// ============================================
// Item Manager (Study Builder)
// ============================================

function initItemManager() {
    const itemForm = document.getElementById('item-form');
    const itemInput = document.getElementById('item-input');

    if (itemForm && itemInput) {
        // Auto-focus on input
        itemInput.focus();

        // Quick add on Enter (submit form)
        itemInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (this.value.trim()) {
                    itemForm.submit();
                }
            }
        });
    }

    // Inline editing for items
    const editButtons = document.querySelectorAll('.item-edit-btn');
    editButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const itemRow = this.closest('.item-row');
            const textSpan = itemRow.querySelector('.item-text');
            const currentText = textSpan.textContent;
            const itemId = this.dataset.itemId;

            // Replace with input
            const input = document.createElement('input');
            input.type = 'text';
            input.value = currentText;
            input.className = 'form-input item-edit-input';
            input.style.flex = '1';

            textSpan.replaceWith(input);
            input.focus();
            input.select();

            // Save on blur or Enter
            const saveEdit = () => {
                const newText = input.value.trim();
                if (newText && newText !== currentText) {
                    // Submit edit
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="update_item">
                        <input type="hidden" name="item_id" value="${itemId}">
                        <input type="hidden" name="item_text" value="${newText}">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                } else {
                    // Revert
                    const span = document.createElement('span');
                    span.className = 'item-text';
                    span.textContent = currentText;
                    input.replaceWith(span);
                }
            };

            input.addEventListener('blur', saveEdit);
            input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    saveEdit();
                }
                if (e.key === 'Escape') {
                    const span = document.createElement('span');
                    span.className = 'item-text';
                    span.textContent = currentText;
                    input.replaceWith(span);
                }
            });
        });
    });
}

// ============================================
// Copy to Clipboard
// ============================================

function initCopyToClipboard() {
    const copyButtons = document.querySelectorAll('[data-copy]');

    copyButtons.forEach(btn => {
        btn.addEventListener('click', async function() {
            const targetId = this.dataset.copy;
            const targetElement = document.getElementById(targetId);

            if (targetElement) {
                const text = targetElement.value || targetElement.textContent;

                try {
                    await navigator.clipboard.writeText(text);

                    // Show feedback
                    const originalText = this.textContent;
                    this.textContent = 'Copied!';
                    this.classList.add('btn-success');

                    setTimeout(() => {
                        this.textContent = originalText;
                        this.classList.remove('btn-success');
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy:', err);
                }
            }
        });
    });
}

// ============================================
// Confirm Dialogs
// ============================================

function initConfirmDialogs() {
    const confirmForms = document.querySelectorAll('[data-confirm]');

    confirmForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const message = this.dataset.confirm;
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
}

// ============================================
// Chart Drawing (using Canvas API)
// ============================================

function drawTornadoChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const padding = 40;
    const labelWidth = 150;
    const barHeight = 30;
    const barGap = 10;

    // Set canvas size
    canvas.width = canvas.parentElement.offsetWidth;
    canvas.height = (barHeight + barGap) * data.length + padding * 2;

    // Find max value for scaling
    const maxValue = Math.max(...data.map(d => Math.max(d.best, d.worst)));
    const chartWidth = (canvas.width - labelWidth - padding * 2) / 2;

    // Draw center line
    const centerX = padding + chartWidth;
    ctx.strokeStyle = '#E5E5E5';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(centerX + labelWidth / 2, padding);
    ctx.lineTo(centerX + labelWidth / 2, canvas.height - padding);
    ctx.stroke();

    // Draw bars
    data.forEach((item, index) => {
        const y = padding + index * (barHeight + barGap);

        // Best bar (left, green)
        const bestWidth = maxValue > 0 ? (item.best / maxValue) * chartWidth : 0;
        ctx.fillStyle = '#22C55E';
        ctx.fillRect(centerX - bestWidth, y, bestWidth, barHeight);

        // Worst bar (right, red)
        const worstWidth = maxValue > 0 ? (item.worst / maxValue) * chartWidth : 0;
        ctx.fillStyle = '#EF4444';
        ctx.fillRect(centerX + labelWidth, y, worstWidth, barHeight);

        // Label
        ctx.fillStyle = '#1A1A1A';
        ctx.font = '12px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(item.label.substring(0, 20), centerX + labelWidth / 2, y + barHeight / 2);
    });

    // Legend
    ctx.fillStyle = '#22C55E';
    ctx.fillRect(padding, canvas.height - 20, 12, 12);
    ctx.fillStyle = '#1A1A1A';
    ctx.textAlign = 'left';
    ctx.fillText('Best', padding + 18, canvas.height - 14);

    ctx.fillStyle = '#EF4444';
    ctx.fillRect(padding + 80, canvas.height - 20, 12, 12);
    ctx.fillStyle = '#1A1A1A';
    ctx.fillText('Worst', padding + 98, canvas.height - 14);
}

// ============================================
// Utility Functions
// ============================================

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}
