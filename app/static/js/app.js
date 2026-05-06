(function () {
    const data = window.PHISHGUARD_ANALYTICS;
    if (!data) return;

    const activityCanvas = document.getElementById("activityChart");
    if (activityCanvas) {
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
    if (riskCanvas) {
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

    document.querySelectorAll('.toggle-password').forEach(button => {
        button.addEventListener('click', () => {
            const group = button.closest('.input-group');
            const input = group ? group.querySelector('.password-input') : null;
            if (!input) return;
            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            const icon = button.querySelector('i');
            if (icon) {
                icon.classList.toggle('bi-eye');
                icon.classList.toggle('bi-eye-slash');
            }
            button.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
        });
    });
})();
