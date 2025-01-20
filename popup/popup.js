document.addEventListener('DOMContentLoaded', () => {
  const scanButton = document.getElementById('scanButton');
  const results = document.getElementById('results');
  const loadingIndicator = document.getElementById('loadingIndicator');

  scanButton.addEventListener('click', async () => {
    results.innerHTML = '';
    loadingIndicator.classList.remove('hidden');

    try {
      // Get the active tab
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      
      // Ensure we have a valid tab
      if (!tab || !tab.id) {
        throw new Error('No active tab found');
      }

      // Send scan message and wait for response
      const vulnerabilities = await browser.tabs.sendMessage(tab.id, { action: 'scan' });
      
      loadingIndicator.classList.add('hidden');

      if (!vulnerabilities || vulnerabilities.length === 0) {
        results.innerHTML = `
          <div class="vulnerability-item" style="border-left-color: var(--success-color); background-color: #ecfdf5;">
            <h3 style="color: var(--success-color)">Scan Complete</h3>
            <p>No XSS vulnerabilities were detected on this page.</p>
          </div>
        `;
        return;
      }

      // Group vulnerabilities by risk level
      const riskLevels = {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
      };

      vulnerabilities.forEach(vuln => {
        if (riskLevels[vuln.riskLevel]) {
          riskLevels[vuln.riskLevel].push(vuln);
        }
      });

      // Display summary
      const totalVulns = vulnerabilities.length;
      results.innerHTML = `
        <div class="summary">
          <h3>Scan Results</h3>
          <p>Found ${totalVulns} potential ${totalVulns === 1 ? 'vulnerability' : 'vulnerabilities'}</p>
        </div>
      `;

      // Display vulnerabilities grouped by risk level
      Object.entries(riskLevels).forEach(([level, vulns]) => {
        if (vulns.length > 0) {
          vulns.forEach(vuln => {
            const vulnElement = document.createElement('div');
            vulnElement.className = 'vulnerability-item';
            vulnElement.innerHTML = `
              <h3>${vuln.type}</h3>
              <p><strong>Risk Level:</strong> <span class="risk-${level.toLowerCase()}">${level}</span></p>
              <p><strong>Location:</strong> ${vuln.location}</p>
              <p><strong>Description:</strong> ${vuln.description}</p>
            `;
            results.appendChild(vulnElement);
          });
        }
      });
    } catch (error) {
      loadingIndicator.classList.add('hidden');
      results.innerHTML = `
        <div class="vulnerability-item" style="border-left-color: var(--danger-color);">
          <h3>Error</h3>
          <p>Unable to scan this page. This might happen if:</p>
          <ul>
            <li>The page is still loading</li>
            <li>The page doesn't allow content scripts</li>
            <li>The page is a browser internal page</li>
          </ul>
          <p>Try refreshing the page and scanning again.</p>
        </div>
      `;
    }
  });
});