// XSS Scanner implementation
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scan') {
    const results = scanForXSS();
    return Promise.resolve(results);
  }
});

function scanForXSS() {
  const vulnerabilities = [];
  
  // Scan input fields for potential XSS vectors
  const inputs = document.querySelectorAll('input, textarea');
  inputs.forEach(input => {
    // Check for missing XSS protections
    if (!input.hasAttribute('sanitized') && !input.hasAttribute('pattern')) {
      const inputType = input.getAttribute('type') || 'text';
      if (['text', 'search', 'url', 'tel', 'email', 'textarea'].includes(inputType)) {
        vulnerabilities.push({
          type: 'Unsanitized Input',
          location: getXPath(input),
          riskLevel: 'High',
          description: 'Input field lacks XSS protection mechanisms'
        });
      }
    }
  });

  // Scan for dangerous DOM manipulation
  const scripts = document.getElementsByTagName('script');
  for (const script of scripts) {
    const content = script.textContent || '';
    const dangerousPatterns = [
      { pattern: /innerHTML\s*=/, risk: 'High', type: 'Unsafe DOM Manipulation' },
      { pattern: /document\.write\(/, risk: 'High', type: 'Unsafe Document Write' },
      { pattern: /eval\(/, risk: 'Critical', type: 'Dangerous Eval Usage' },
      { pattern: /fromCharCode|String\.raw`/, risk: 'Medium', type: 'Potential String Manipulation' }
    ];

    dangerousPatterns.forEach(({ pattern, risk, type }) => {
      if (pattern.test(content)) {
        vulnerabilities.push({
          type,
          location: getXPath(script),
          riskLevel: risk,
          description: `Found potentially dangerous JavaScript pattern: ${pattern.toString()}`
        });
      }
    });
  }

  // Scan for unsafe event handlers
  const allElements = document.getElementsByTagName('*');
  for (const element of allElements) {
    // Check inline event handlers
    const attributes = Array.from(element.attributes);
    attributes.forEach(attr => {
      if (attr.name.toLowerCase().startsWith('on')) {
        vulnerabilities.push({
          type: 'Inline Event Handler',
          location: getXPath(element),
          riskLevel: 'Medium',
          description: `Potentially unsafe inline event handler: ${attr.name}`
        });
      }
    });

    // Check for dangerous href attributes
    if (element.tagName === 'A') {
      const href = element.getAttribute('href');
      if (href && (href.startsWith('javascript:') || href.includes('data:'))) {
        vulnerabilities.push({
          type: 'Dangerous URL',
          location: getXPath(element),
          riskLevel: 'High',
          description: 'Link contains potentially malicious protocol'
        });
      }
    }
  }

  // Scan for reflected content in URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  for (const [param, value] of urlParams) {
    if (value.length > 0) {
      // Search in text content
      const bodyText = document.body.innerHTML;
      if (bodyText.includes(value)) {
        vulnerabilities.push({
          type: 'Reflected Content',
          location: `URL Parameter: ${param}`,
          riskLevel: 'High',
          description: `URL parameter value is reflected in page content without proper encoding`
        });
      }

      // Check for parameter pollution
      if (document.querySelector(`[name="${param}"]`) || document.querySelector(`[id="${param}"]`)) {
        vulnerabilities.push({
          type: 'Parameter Pollution',
          location: `URL Parameter: ${param}`,
          riskLevel: 'Medium',
          description: 'URL parameter matches DOM element identifier'
        });
      }
    }
  }

  // Check for vulnerable iframe usage
  const iframes = document.getElementsByTagName('iframe');
  for (const iframe of iframes) {
    if (!iframe.hasAttribute('sandbox')) {
      vulnerabilities.push({
        type: 'Unsafe iFrame',
        location: getXPath(iframe),
        riskLevel: 'Medium',
        description: 'iFrame without sandbox attribute may be vulnerable to XSS'
      });
    }
  }

  return vulnerabilities;
}

// Helper function to get XPath of an element
function getXPath(element) {
  try {
    if (element.id) {
      return `//*[@id="${element.id}"]`;
    }
    if (element === document.body) {
      return '/html/body';
    }

    let path = '';
    while (element.parentNode) {
      let siblings = element.parentNode.childNodes;
      let index = 1;
      for (let sibling of siblings) {
        if (sibling === element) {
          path = `/${element.tagName.toLowerCase()}[${index}]${path}`;
          break;
        }
        if (sibling.nodeType === 1 && sibling.tagName === element.tagName) {
          index++;
        }
      }
      element = element.parentNode;
    }
    return path;
  } catch (error) {
    return 'Unknown location';
  }
}