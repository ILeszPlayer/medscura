(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        autoFadeAlerts();
        confirmDialogs();
        autoTrimInputs();
    });

    function autoFadeAlerts() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function (alert) {
            setTimeout(function () {
                var bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        });
    }

    function confirmDialogs() {
        document.querySelectorAll('[data-confirm]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                if (!confirm(el.getAttribute('data-confirm') || 'Are you sure?')) {
                    e.preventDefault();
                }
            });
        });
    }

    function autoTrimInputs() {
        document.querySelectorAll('form').forEach(function (form) {
            form.addEventListener('submit', function () {
                var inputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="search"], textarea');
                inputs.forEach(function (input) {
                    input.value = input.value.trim();
                });
            });
        });
    }

    function sanitizeInput(input) {
        var temp = document.createElement('div');
        temp.textContent = input;
        return temp.innerHTML;
    }

    window.addEventListener('error', function (e) {
        console.error('Application error:', e.message);
        return true;
    });

})();
