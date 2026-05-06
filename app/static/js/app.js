(function () {
    const data = window.PHISHGUARD_ANALYTICS;

    const activityCanvas = document.getElementById("activityChart");
    if (activityCanvas && data) {
        new Chart(activityCanvas, {
            type: "line",
            data: {
                labels: data.activityLabels || [],
                datasets: [{
                    label: "Scans",
                    data: data.activityValues || [],
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    backgroundColor: "rgba(24, 180, 191, 0.12)",
                    borderColor: "#18b4bf",
                    pointBackgroundColor: "#0f4c81"
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
            }
        });
    }

    const riskCanvas = document.getElementById("riskChart");
    if (riskCanvas && data) {
        new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: ["Low", "Medium", "High"],
                datasets: [{
                    data: data.riskValues || [0, 0, 0],
                    backgroundColor: ["#7ed6a7", "#ffd166", "#f28482"],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { position: "bottom" } }
            }
        });
    }

    document.querySelectorAll('.password-toggle-icon').forEach(icon => {
        icon.addEventListener('click', () => {
            const wrapper = icon.closest('.position-relative');
            const input = wrapper ? wrapper.querySelector('.password-input') : null;
            if (!input) return;
            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            const iconEl = icon.querySelector('i');
            if (iconEl) {
                iconEl.classList.toggle('bi-eye');
                iconEl.classList.toggle('bi-eye-slash');
            }
            icon.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
        });
    });

    function setFieldError(input, message) {
        let wrapper = input.parentElement;
        while (wrapper && !wrapper.querySelector('.invalid-feedback')) {
            wrapper = wrapper.parentElement;
        }
        const feedback = wrapper ? wrapper.querySelector('.invalid-feedback') : null;
        if (message) {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            if (feedback) {
                feedback.textContent = message;
            }
        } else {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            if (feedback) {
                feedback.textContent = '';
            }
        }
    }

    function validateInputField(input) {
        const value = input.value.trim();
        if (!value) {
            return 'This field is required.';
        }
        if (input.type === 'email') {
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                return 'Enter a valid email address.';
            }
        }
        if (input.name === 'password') {
            if (value.length < 8) {
                return 'Use at least 8 characters for your password.';
            }
        }
        if (input.name === 'confirm_password') {
            const form = input.closest('form');
            const passwordField = form ? form.querySelector('[name="password"]') : null;
            if (passwordField && value !== passwordField.value.trim()) {
                return 'Passwords must match.';
            }
        }
        return '';
    }

    document.querySelectorAll('.auth-validate-form').forEach(form => {
        const inputs = Array.from(form.querySelectorAll('input'));
        inputs.forEach(input => {
            input.addEventListener('input', () => {
                setFieldError(input, validateInputField(input));
            });
        });

        form.addEventListener('submit', event => {
            let formIsValid = true;
            inputs.forEach(input => {
                const message = validateInputField(input);
                setFieldError(input, message);
                if (message) {
                    formIsValid = false;
                }
            });
            if (!formIsValid) {
                event.preventDefault();
                event.stopPropagation();
            }
        });
    });
})();
