// Chart.js global defaults for SOC theme
Chart.defaults.color = '#8a9fac';
Chart.defaults.font.family = '"Fira Code", monospace';
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(10, 17, 24, 0.9)';
Chart.defaults.plugins.tooltip.borderColor = '#00f0ff';
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.titleColor = '#00f0ff';
Chart.defaults.plugins.tooltip.bodyColor = '#e0e6ed';
Chart.defaults.plugins.legend.labels.color = '#8a9fac';

const chartColors = {
    cyan: '#00f0ff',
    cyanDim: 'rgba(0, 240, 255, 0.2)',
    red: '#ff003c',
    redDim: 'rgba(255, 0, 60, 0.2)',
    green: '#00ff41',
    greenDim: 'rgba(0, 255, 65, 0.2)',
    yellow: '#ffaa00',
    yellowDim: 'rgba(255, 170, 0, 0.2)',
    magenta: '#ff00ff'
};

document.addEventListener('DOMContentLoaded', () => {
    // 1. Events Over Time (Area Chart)
    const ctxTimeline = document.getElementById('chart-events-timeline');
    if (ctxTimeline) {
        new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: ['18:50', '18:55', '19:00', '19:05', '19:10', '19:15', '19:20', '19:25'],
                datasets: [
                    {
                        label: 'alert',
                        data: [0, 0, 0, 0, 0, 0, 0, 0],
                        borderColor: chartColors.red,
                        backgroundColor: chartColors.redDim,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: 'http',
                        data: [0, 0, 0, 0, 0, 0, 0, 0],
                        borderColor: chartColors.cyan,
                        backgroundColor: chartColors.cyanDim,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: 'rgba(26, 43, 60, 0.5)' } },
                    y: { grid: { color: 'rgba(26, 43, 60, 0.5)' }, beginAtZero: true, suggestedMax: 100 }
                },
                plugins: {
                    legend: { position: 'top', align: 'start', labels: { boxWidth: 10, usePointStyle: true } }
                }
            }
        });
    }

    // Common options for Donuts
    const donutOptions = {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
            legend: { display: false }
        }
    };

    // 2. Event Types
    const ctxEventTypes = document.getElementById('chart-event-types');
    if (ctxEventTypes) {
        new Chart(ctxEventTypes, {
            type: 'doughnut',
            data: {
                labels: ['Awaiting Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['rgba(26, 43, 60, 0.5)'],
                    borderColor: ['rgba(26, 43, 60, 1)'],
                    borderWidth: 1
                }]
            },
            options: donutOptions
        });
    }

    // 3. HTTP Version
    const ctxHttpVersion = document.getElementById('chart-http-version');
    if (ctxHttpVersion) {
        new Chart(ctxHttpVersion, {
            type: 'doughnut',
            data: {
                labels: ['Awaiting Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['rgba(26, 43, 60, 0.5)'],
                    borderColor: ['rgba(26, 43, 60, 1)'],
                    borderWidth: 1
                }]
            },
            options: donutOptions
        });
    }

    // 4. HTTP Methods
    const ctxHttpMethods = document.getElementById('chart-http-methods');
    if (ctxHttpMethods) {
        new Chart(ctxHttpMethods, {
            type: 'doughnut',
            data: {
                labels: ['Awaiting Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['rgba(26, 43, 60, 0.5)'],
                    borderColor: ['rgba(26, 43, 60, 1)'],
                    borderWidth: 1
                }]
            },
            options: donutOptions
        });
    }

    // 5. TLS Version
    const ctxTlsVersion = document.getElementById('chart-tls-version');
    if (ctxTlsVersion) {
        new Chart(ctxTlsVersion, {
            type: 'doughnut',
            data: {
                labels: ['Awaiting Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['rgba(26, 43, 60, 0.5)'],
                    borderColor: ['rgba(26, 43, 60, 1)'],
                    borderWidth: 1
                }]
            },
            options: donutOptions
        });
    }

    // 6. HTTP Status Codes (Bar Chart)
    const ctxHttpStatus = document.getElementById('chart-http-status');
    if (ctxHttpStatus) {
        new Chart(ctxHttpStatus, {
            type: 'bar',
            data: {
                labels: ['200', '301', '404', '500'],
                datasets: [{
                    label: 'Count',
                    data: [0, 0, 0, 0],
                    backgroundColor: [chartColors.green, chartColors.cyan, chartColors.yellow, chartColors.red],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: 'rgba(26, 43, 60, 0.5)' }, beginAtZero: true, suggestedMax: 10, display: false }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
});
