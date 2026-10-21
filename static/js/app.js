/**
 * app.js
 * Automated Web Security Scanner — Frontend JavaScript
 *
 * Responsibilities:
 *  - Initialize Chart.js charts for the dashboard and results pages.
 *  - Provide helper functions called from inline <script> blocks in templates.
 */

'use strict';

// ── Colour palette (matches style.css) ──────────────────────────────────────
const SEVERITY_COLORS = {
  Critical:      '#dc2626',
  High:          '#ea580c',
  Medium:        '#ca8a04',
  Low:           '#2563eb',
  Informational: '#6b7280',
};

const SEVERITY_BG = {
  Critical:      'rgba(220,38,38,0.15)',
  High:          'rgba(234,88,12,0.15)',
  Medium:        'rgba(202,138,4,0.15)',
  Low:           'rgba(37,99,235,0.15)',
  Informational: 'rgba(107,114,128,0.15)',
};

const CHART_DEFAULTS = {
  font: { family: '-apple-system,"Segoe UI",system-ui,sans-serif' },
  color: '#57606a',
};

// Apply global Chart.js defaults once
if (typeof Chart !== 'undefined') {
  Chart.defaults.font.family = CHART_DEFAULTS.font.family;
  Chart.defaults.color       = CHART_DEFAULTS.color;
}

// ── Dashboard Charts ─────────────────────────────────────────────────────────
/**
 * initDashboardCharts(data)
 * Called from templates/index.html when session-level stats are available.
 *
 * @param {Object} data  { labels: string[], values: number[] }
 */
function initDashboardCharts(data) {
  const labels = data.labels;
  const values = data.values;

  const bgColors  = labels.map(l => SEVERITY_BG[l]   || 'rgba(100,100,100,0.15)');
  const brdColors = labels.map(l => SEVERITY_COLORS[l] || '#999');

  // ── Doughnut chart ──────────────────────────────────────────────────────
  const ctxPie = document.getElementById('severityChart');
  if (ctxPie) {
    new Chart(ctxPie, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: brdColors,
          borderColor: '#ffffff',
          borderWidth: 2,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          legend: {
            position: 'right',
            labels: { boxWidth: 12, padding: 14, font: { size: 12 } },
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed}`,
            },
          },
        },
      },
    });
  }

  // ── Horizontal bar chart ─────────────────────────────────────────────────
  const ctxBar = document.getElementById('barChart');
  if (ctxBar) {
    new Chart(ctxBar, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Findings',
          data: values,
          backgroundColor: brdColors,
          borderColor: brdColors,
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.parsed.x} findings`,
            },
          },
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { precision: 0 },
            grid: { color: 'rgba(0,0,0,0.05)' },
          },
          y: {
            grid: { display: false },
          },
        },
      },
    });
  }
}

// ── Results page doughnut ─────────────────────────────────────────────────────
/**
 * initResultDonut(data)
 * Called from templates/results.html.
 */
function initResultDonut(data) {
  const labels = data.labels;
  const values = data.values;

  const brdColors = labels.map(l => SEVERITY_COLORS[l] || '#999');

  const ctx = document.getElementById('resultDonut');
  if (!ctx) return;

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: brdColors,
        borderColor: '#ffffff',
        borderWidth: 2,
        hoverOffset: 5,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '58%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { boxWidth: 10, padding: 10, font: { size: 11 } },
        },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed}`,
          },
        },
      },
    },
  });
}

// ── Auto-dismiss alerts after 8 seconds ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.alert.alert-dismissible').forEach(el => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      if (bsAlert) bsAlert.close();
    }, 8000);
  });
});
