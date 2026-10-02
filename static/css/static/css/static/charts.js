// charts.js
// Draws the dashboard and analysis charts. All data comes from the
// Python engines via the page - this file does no calculation.

var LEVEL_COLOURS = ["#E45A5A", "#E08A3C", "#D9C24A", "#5AB98A"];
var GRID = "#392F47";
var TICK = "#9A8FA8";

function drawCharts(levels, algoNames, algoCounts) {

  var d1 = document.getElementById("riskChart");
  if (d1) {
    new Chart(d1, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: levels,
          backgroundColor: LEVEL_COLOURS,
          borderColor: "#211A2A",
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { color: TICK, padding: 14, boxWidth: 12 }
          }
        }
      }
    });
  }

  var d2 = document.getElementById("algoChart");
  if (d2) {
    new Chart(d2, {
      type: "bar",
      data: {
        labels: algoNames,
        datasets: [{
          label: "Systems",
          data: algoCounts,
          backgroundColor: "#E0A22E",
          borderRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: TICK }, grid: { color: GRID } },
          y: { ticks: { color: TICK, stepSize: 1 },
               grid: { color: GRID }, beginAtZero: true }
        }
      }
    });
  }
}

function drawTopChart(names, scores) {
  var el = document.getElementById("topChart");
  if (!el) return;

  var colours = scores.map(function (s) {
    if (s >= 75) return LEVEL_COLOURS[0];
    if (s >= 55) return LEVEL_COLOURS[1];
    if (s >= 35) return LEVEL_COLOURS[2];
    return LEVEL_COLOURS[3];
  });

  new Chart(el, {
    type: "bar",
    data: {
      labels: names,
      datasets: [{
        label: "Risk %",
        data: scores,
        backgroundColor: colours,
        borderRadius: 3
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { max: 100, ticks: { color: TICK }, grid: { color: GRID } },
        y: { ticks: { color: TICK }, grid: { display: false } }
      }
    }
  });
}

function drawDeptChart(names, averages) {
  var el = document.getElementById("deptChart");
  if (!el) return;

  var colours = averages.map(function (a) {
    if (a >= 75) return LEVEL_COLOURS[0];
    if (a >= 55) return LEVEL_COLOURS[1];
    if (a >= 35) return LEVEL_COLOURS[2];
    return LEVEL_COLOURS[3];
  });

  new Chart(el, {
    type: "bar",
    data: {
      labels: names,
      datasets: [{
        label: "Average risk %",
        data: averages,
        backgroundColor: colours,
        borderRadius: 3
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { max: 100, ticks: { color: TICK }, grid: { color: GRID } },
        y: { ticks: { color: TICK }, grid: { display: false } }
      }
    }
  });
}

// Risk Analysis: the three plain answers as a doughnut.
function drawStateChart(counts) {
  var el = document.getElementById("stateChart");
  if (!el) return;
  new Chart(el, {
    type: "doughnut",
    data: {
      labels: ["Too late", "Still time", "Safe"],
      datasets: [{ data: counts,
                   backgroundColor: ["#E45A5A", "#D9C24A", "#5AB98A"],
                   borderColor: "#211A2A", borderWidth: 2 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "58%",
      plugins: { legend: { position: "right",
                 labels: { color: TICK, padding: 14, boxWidth: 12 } } }
    }
  });
}

// Risk Analysis: which locks are in use, coloured by what a quantum
// computer does to them.
function drawLockChart(names, counts, colours) {
  var el = document.getElementById("lockChart");
  if (!el) return;
  new Chart(el, {
    type: "bar",
    data: { labels: names,
            datasets: [{ label: "Systems", data: counts,
                         backgroundColor: colours, borderRadius: 3 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: TICK }, grid: { display: false } },
        y: { ticks: { color: TICK, stepSize: 5 }, grid: { color: GRID },
             beginAtZero: true,
             title: { display: true, text: "number of systems", color: TICK } }
      }
    }
  });
}
