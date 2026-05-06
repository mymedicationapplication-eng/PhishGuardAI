(function () {
    // Define showToast globally before DOMContentLoaded
    window.showToast = function(message, category = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `custom-toast ${category}`;

        const iconMap = {
            success: 'bi-check-circle-fill',
            danger: 'bi-x-circle-fill',
            error: 'bi-x-circle-fill',
            warning: 'bi-exclamation-triangle-fill',
            info: 'bi-info-circle-fill'
        };

        const icon = iconMap[category] || iconMap.info;

        toast.innerHTML = `
            <div class="custom-toast-icon">
                <i class="bi ${icon}"></i>
            </div>
            <div class="custom-toast-content">${message}</div>
            <button class="custom-toast-close" aria-label="Close">
                <i class="bi bi-x"></i>
            </button>
        `;

        container.appendChild(toast);

        const closeBtn = toast.querySelector('.custom-toast-close');
        closeBtn.addEventListener('click', () => {
            toast.classList.add('hiding');
            setTimeout(() => toast.remove(), 300);
        });

        setTimeout(() => {
            toast.classList.add('hiding');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    };

    // Wait for DOM to be fully loaded
    document.addEventListener('DOMContentLoaded', function() {
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

        // Password toggle functionality
        document.querySelectorAll('.password-toggle-icon').forEach(icon => {
            icon.addEventListener('click', function() {
                const wrapper = this.closest('.position-relative');
                const input = wrapper ? wrapper.querySelector('.password-input') : null;
                if (!input) return;
                
                const isHidden = input.type === 'password';
                input.type = isHidden ? 'text' : 'password';
                
                const iconEl = this.querySelector('i');
                if (iconEl) {
                    iconEl.classList.toggle('bi-eye');
                    iconEl.classList.toggle('bi-eye-slash');
                }
                
                this.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
            });
        });

        // Real-time validation functions
        function showFieldToast(message, category = 'error') {
            showToast(message, category);
        }

        function validateInputField(input, isRegisterPage = false) {
            const value = input.value.trim();
            
            if (!value && input.hasAttribute('required')) {
                return 'Please fill in this field.';
            }
            
            if (input.type === 'email' && value) {
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                    return 'Please enter a valid email address.';
                }
            }
            
            // Only validate password strength on register page
            if (input.name === 'password' && value && isRegisterPage) {
                if (value.length < 8) {
                    return 'Password must be at least 8 characters long.';
                }
                if (!/(?=.*[a-z])/.test(value)) {
                    return 'Password must include at least one lowercase letter.';
                }
                if (!/(?=.*[A-Z])/.test(value)) {
                    return 'Password must include at least one uppercase letter.';
                }
                if (!/(?=.*\d)/.test(value)) {
                    return 'Password must include at least one number.';
                }
            }
            
            if (input.name === 'confirm_password' && value && isRegisterPage) {
                const form = input.closest('form');
                const passwordField = form ? form.querySelector('[name="password"]') : null;
                if (passwordField && value !== passwordField.value.trim()) {
                    return 'Passwords do not match. Please try again.';
                }
            }
            
            if (input.name === 'full_name' && value) {
                if (value.length < 2) {
                    return 'Name must be at least 2 characters long.';
                }
                if (!/^[a-zA-Z\s]+$/.test(value)) {
                    return 'Name can only contain letters and spaces.';
                }
            }
            
            return '';
        }

        // Apply validation to all auth forms
        const authForms = document.querySelectorAll('form');
        authForms.forEach(form => {
            const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]');
            const isRegisterPage = form.querySelector('[name="full_name"]') !== null;
            
            // Form submission validation only
            form.addEventListener('submit', function(event) {
                let formIsValid = true;
                let errorMessages = [];
                
                inputs.forEach(input => {
                    const message = validateInputField(input, isRegisterPage);
                    if (message) {
                        formIsValid = false;
                        errorMessages.push(message);
                        input.classList.add('is-invalid');
                    } else {
                        input.classList.remove('is-invalid');
                    }
                });
                
                if (!formIsValid) {
                    event.preventDefault();
                    event.stopPropagation();
                    
                    // Show first error message in toast
                    if (errorMessages.length > 0) {
                        showFieldToast(errorMessages[0], 'error');
                    }
                    
                    // Focus on first invalid field
                    const firstInvalid = form.querySelector('.is-invalid');
                    if (firstInvalid) {
                        firstInvalid.focus();
                    }
                }
            });
            
            // Clear validation styling on input
            inputs.forEach(input => {
                input.addEventListener('input', function() {
                    this.classList.remove('is-invalid');
                });
                
                input.addEventListener('focus', function() {
                    this.classList.remove('is-invalid');
                });
            });
        });
    });
})();