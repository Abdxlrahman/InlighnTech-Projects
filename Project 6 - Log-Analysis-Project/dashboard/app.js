// App Logic for Aegis SIEM Dashboard
document.addEventListener("DOMContentLoaded", () => {
    // Default system log placeholder if log_data.js isn't populated
    let logContent = typeof rawLogData !== "undefined" ? rawLogData : "";
    
    // Parse parameters
    let logs = [];
    let charts = {};

    const elements = {
        totalLogs: document.getElementById("total-logs"),
        failedLogins: document.getElementById("failed-logins"),
        successLogins: document.getElementById("success-logins"),
        incidentsCount: document.getElementById("incidents-count"),
        attackerTable: document.getElementById("attacker-table-body"),
        alertsFeed: document.getElementById("security-alerts-feed"),
        terminal: document.getElementById("log-terminal"),
        search: document.getElementById("log-search"),
        filter: document.getElementById("log-filter"),
        upload: document.getElementById("log-upload")
    };

    // Initialize File Upload Reader
    elements.upload.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (evt) => {
            logContent = evt.target.result;
            processLogData(logContent);
        };
        reader.readAsText(file);
    });

    // Initialize Log search & filters
    elements.search.addEventListener("input", filterAndRenderLogs);
    elements.filter.addEventListener("change", filterAndRenderLogs);

    // Initial Process
    if (logContent) {
        processLogData(logContent);
    }

    function processLogData(rawLogs) {
        // Clear previous state
        logs = [];
        const rawLines = rawLogs.trim().split("\n");
        
        let failedCount = 0;
        let successCount = 0;
        let incidentCount = 0;

        const failedIPs = {};
        const failedUsers = {};
        const successLoginsList = [];
        const sudoActions = [];
        const alerts = [];

        // Parse lines
        rawLines.forEach((line) => {
            if (!line.trim()) return;

            // Extract timestamp, server name, process, message
            // Jun 24 10:15:32 debian-server sshd[1234]: Connection from...
            const parts = line.match(/^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?):\s+(.*)$/);
            
            let parsed = {
                raw: line,
                timestamp: "Unknown",
                process: "Unknown",
                message: line,
                type: "info"
            };

            if (parts) {
                parsed.timestamp = parts[1];
                parsed.process = parts[3];
                parsed.message = parts[4];
            }

            // Identify event types
            const msg = parsed.message;
            if (msg.includes("Failed password")) {
                parsed.type = "failed";
                failedCount++;
                const ipMatch = msg.match(/from ([\d\.]+) port/);
                const userMatch = msg.match(/for (\S+) from/);
                if (ipMatch && userMatch) {
                    const ip = ipMatch[1];
                    const user = userMatch[1];
                    failedIPs[ip] = (failedIPs[ip] || 0) + 1;
                    if (!failedUsers[ip]) failedUsers[ip] = new Set();
                    failedUsers[ip].add(user);
                }
            } else if (msg.includes("Accepted password")) {
                parsed.type = "success";
                successCount++;
                const ipMatch = msg.match(/from ([\d\.]+) port/);
                const userMatch = msg.match(/for (\S+) from/);
                if (ipMatch && userMatch) {
                    successLoginsList.push({
                        time: parsed.timestamp,
                        user: userMatch[1],
                        ip: ipMatch[1]
                    });
                }
            } else if (parsed.process.includes("sudo") || msg.includes("sudo:")) {
                parsed.type = "sudo";
                sudoActions.push({
                    time: parsed.timestamp,
                    message: msg
                });
                
                if (msg.includes("command not allowed")) {
                    parsed.type = "denied";
                    incidentCount++;
                    alerts.push({
                        type: "critical",
                        title: "Unauthorized Sudo Attempt",
                        desc: msg,
                        time: parsed.timestamp
                    });
                } else if (msg.includes("/bin/bash") || msg.includes("/bin/sh")) {
                    parsed.type = "sudo-escalate";
                    incidentCount++;
                    alerts.push({
                        type: "critical",
                        title: "Privilege Escalation (Shell)",
                        desc: `User escalated privileges via: ${msg}`,
                        time: parsed.timestamp
                    });
                }
            } else if (msg.includes("new user: name=backdoor") || msg.includes("name=backuser")) {
                parsed.type = "backdoor";
                incidentCount++;
                alerts.push({
                    type: "critical",
                    title: "Backdoor User Created",
                    desc: `New local user configuration detected: ${msg}`,
                    time: parsed.timestamp
                });
            }

            logs.push(parsed);
        });

        // Detect brute force sources (> 10 failed logins) and alert
        Object.keys(failedIPs).forEach((ip) => {
            if (failedIPs[ip] >= 10) {
                incidentCount++;
                alerts.push({
                    type: "warning",
                    title: "Brute Force Attack Detected",
                    desc: `IP ${ip} attempted ${failedIPs[ip]} failed logins targeting: ${Array.from(failedUsers[ip]).join(", ")}`,
                    time: "Multiple Matches"
                });
                
                // Cross reference success
                successLoginsList.forEach((success) => {
                    if (success.ip === ip) {
                        incidentCount += 2; // Increase weights for compromises
                        alerts.push({
                            type: "critical",
                            title: "COMPROMISED HOST (Successful Login after Brute Force)",
                            desc: `Account '${success.user}' compromised from attacking IP ${ip}`,
                            time: success.time
                        });
                    }
                });
            }
        });

        // Update Dashboard GUI metrics
        elements.totalLogs.innerText = logs.length.toLocaleString();
        elements.failedLogins.innerText = failedCount.toLocaleString();
        elements.successLogins.innerText = successCount.toLocaleString();
        elements.incidentsCount.innerText = incidentCount.toLocaleString();

        // Render sections
        renderAttackerTable(failedIPs, failedUsers);
        renderAlerts(alerts);
        filterAndRenderLogs();
        renderCharts(failedCount, successCount, logs);
    }

    function renderAttackerTable(failedIPs, failedUsers) {
        elements.attackerTable.innerHTML = "";
        
        const sortedAttackers = Object.entries(failedIPs).sort((a, b) => b[1] - a[1]);
        
        if (sortedAttackers.length === 0) {
            elements.attackerTable.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-secondary);">No attack traffic detected.</td></tr>`;
            return;
        }

        sortedAttackers.forEach(([ip, count]) => {
            const users = Array.from(failedUsers[ip] || []).join(", ");
            const isCritical = count >= 10;
            const badgeClass = isCritical ? "badge critical" : "badge safe";
            const badgeText = isCritical ? "Critical Threat" : "Suspicious";
            const recommendation = isCritical ? "Add block rule in iptables / firewalld" : "Monitor traffic";

            const row = document.createElement("tr");
            row.innerHTML = `
                <td><strong>${ip}</strong></td>
                <td>${count}</td>
                <td><code style="font-family: var(--font-mono); font-size: 0.75rem;">${users}</code></td>
                <td><span class="${badgeClass}">${badgeText}</span></td>
                <td>
                    <button class="btn-action" onclick="alert('Suggested Command:\\nsudo iptables -A INPUT -s ${ip} -j DROP')">
                        <i class="fa-solid fa-ban"></i> Generate Block Command
                    </button>
                </td>
            `;
            elements.attackerTable.appendChild(row);
        });
    }

    function renderAlerts(alerts) {
        elements.alertsFeed.innerHTML = "";
        if (alerts.length === 0) {
            elements.alertsFeed.innerHTML = `<div class="incident-item info"><div class="incident-title">System Secure</div><div class="incident-desc">No events matched alert indicators.</div></div>`;
            return;
        }

        alerts.forEach((alert) => {
            const item = document.createElement("div");
            item.className = `incident-item ${alert.type}`;
            item.innerHTML = `
                <div class="incident-meta">
                    <span class="incident-time">${alert.time}</span>
                    <span class="badge ${alert.type}">${alert.type}</span>
                </div>
                <div class="incident-title">${alert.title}</div>
                <div class="incident-desc">${alert.desc}</div>
            `;
            elements.alertsFeed.appendChild(item);
        });
    }

    function filterAndRenderLogs() {
        const query = elements.search.value.toLowerCase();
        const filterType = elements.filter.value;
        elements.terminal.innerHTML = "";

        const filtered = logs.filter((log) => {
            // Search query filter
            const matchesQuery = log.raw.toLowerCase().includes(query);
            if (!matchesQuery) return false;

            // Category filter
            if (filterType === "all") return true;
            if (filterType === "failed" && log.type === "failed") return true;
            if (filterType === "success" && log.type === "success") return true;
            if (filterType === "sudo" && (log.type === "sudo" || log.type === "denied" || log.type === "sudo-escalate")) return true;
            if (filterType === "backdoor" && log.type === "backdoor") return true;

            return false;
        });

        if (filtered.length === 0) {
            elements.terminal.innerHTML = `<div style="color: #666; font-style: italic;">No matching logs found.</div>`;
            return;
        }

        // Output lines to explorer console
        filtered.forEach((log) => {
            const logLine = document.createElement("div");
            
            // Apply standard syslog coloration matching severity
            if (log.type === "failed") {
                logLine.style.color = "var(--neon-red)";
            } else if (log.type === "success") {
                logLine.style.color = "var(--neon-green)";
            } else if (log.type === "denied") {
                logLine.style.color = "var(--neon-orange)";
                logLine.style.fontWeight = "bold";
            } else if (log.type === "sudo-escalate") {
                logLine.style.color = "var(--neon-purple)";
                logLine.style.fontWeight = "bold";
            } else if (log.type === "backdoor") {
                logLine.style.color = "var(--neon-purple)";
                logLine.style.border = "1px dashed var(--neon-purple)";
                logLine.style.padding = "2px";
            } else {
                logLine.style.color = "var(--text-secondary)";
            }

            logLine.innerText = log.raw;
            elements.terminal.appendChild(logLine);
        });
        
        // Auto scroll terminal to top
        elements.terminal.scrollTop = 0;
    }

    function renderCharts(failedCount, successCount, logs) {
        // Destroy existing charts to recreate cleanly on reload
        if (charts.ratio) charts.ratio.destroy();
        if (charts.timeline) charts.timeline.destroy();

        // 1. Ratio Chart (Pie/Doughnut)
        const ratioCtx = document.getElementById("ratioChart").getContext("2d");
        charts.ratio = new Chart(ratioCtx, {
            type: 'doughnut',
            data: {
                labels: ['Failed Auths', 'Successful Auths'],
                datasets: [{
                    data: [failedCount, successCount],
                    backgroundColor: ['#ff0055', '#39ff14'],
                    borderColor: '#121026',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#a29fc5',
                            font: { family: 'Outfit' }
                        }
                    }
                }
            }
        });

        // 2. Timeline Chart (Authentication timeline counts by hour)
        // Group logs by hour
        const hourlyData = {};
        logs.forEach(log => {
            if (log.timestamp !== "Unknown") {
                // Extract "Month Day Hour" e.g., "Jun 24 10"
                const hourStr = log.timestamp.substring(0, 10);
                if (!hourlyData[hourStr]) {
                    hourlyData[hourStr] = { success: 0, failed: 0 };
                }
                if (log.type === "failed") {
                    hourlyData[hourStr].failed++;
                } else if (log.type === "success") {
                    hourlyData[hourStr].success++;
                }
            }
        });

        const sortedHours = Object.keys(hourlyData).sort();
        const timelineLabels = sortedHours.map(h => h + ":00");
        const failedSeries = sortedHours.map(h => hourlyData[h].failed);
        const successSeries = sortedHours.map(h => hourlyData[h].success);

        const timelineCtx = document.getElementById("timelineChart").getContext("2d");
        charts.timeline = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: timelineLabels,
                datasets: [
                    {
                        label: 'Failed SSH Attempts',
                        data: failedSeries,
                        borderColor: '#ff0055',
                        backgroundColor: 'rgba(255, 0, 85, 0.1)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'Successful SSH Logins',
                        data: successSeries,
                        borderColor: '#39ff14',
                        backgroundColor: 'rgba(57, 255, 20, 0.1)',
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: { color: '#a29fc5', font: { family: 'Outfit' } },
                        grid: { color: '#242045' }
                    },
                    y: {
                        ticks: { color: '#a29fc5', font: { family: 'Outfit' } },
                        grid: { color: '#242045' }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#a29fc5',
                            font: { family: 'Outfit' }
                        }
                    }
                }
            }
        });
    }
});
