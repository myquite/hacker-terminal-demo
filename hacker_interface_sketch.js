
// ============================================================================
// HACKER INTERFACE - NETWORK VULNERABILITY SYSTEM
// ============================================================================

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

// Core application state
const AppState = {
  currentTime: 0,
  deltaTime: 0,
  lastTime: 0,
  frameCount: 0
};

// Network topology data
const NetworkData = {
  nodes: [],
  hops: [],
  networkTraffic: []
};

// Panel-specific data
const PanelData = {
  terminalLog: [],
  scanResults: [],
  exploitStatus: []
};

// Attack system configuration
const AttackConfig = {
  PHASES: {
    TARGET_SELECTION: 0,
    TERMINAL_COMMAND: 1,
    NETWORK_HIGHLIGHT: 2,
    VULNERABILITY_SCAN: 3,
    EXPLOIT_EXECUTION: 4,
    COMPLETE: 5
  },
  PHASE_DURATION: 3000, // 3 seconds per phase
  PHASE_NAMES: ["TARGET_SELECTION", "TERMINAL_COMMAND", "NETWORK_HIGHLIGHT", "VULNERABILITY_SCAN", "EXPLOIT_EXECUTION", "COMPLETE"]
};

// Attack sequence state
const AttackSequence = {
  currentPhase: 0,
  currentTarget: null,
  currentTargetIndex: 0,
  phaseTimer: 0,
  targets: [],
  attackInProgress: false
};

// Shared attack data for cross-panel coordination
const SharedAttackData = {
  currentTarget: null,
  discoveredVulnerabilities: [],
  successfulExploits: [],
  networkChanges: [],
  lastUpdate: 0
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Calculate responsive text sizes based on window dimensions
 * @param {number} baseSize - Base font size
 * @returns {number} Responsive font size
 */
function getResponsiveTextSize(baseSize) {
  const scaleFactor = min(width / 1200, height / 800);
  return max(baseSize * scaleFactor, baseSize * 0.8);
}

/**
 * Truncate text to fit within specified width
 * @param {string} text - Text to truncate
 * @param {number} maxWidth - Maximum width in pixels
 * @param {number} maxChars - Maximum characters before truncation
 * @returns {string} Truncated text
 */
function truncateText(text, maxWidth, maxChars = 10) {
  if (textWidth(text) > maxWidth) {
    return text.substring(0, maxChars) + "..";
  }
  return text;
}

/**
 * Generate a random IP address
 * @returns {string} Random IP address
 */
function generateRandomIP() {
  return `${floor(random(1, 255))}.${floor(random(0, 255))}.${floor(random(0, 255))}.${floor(random(1, 255))}`;
}

/**
 * Generate a random operating system
 * @returns {string} Random OS name
 */
function generateRandomOS() {
  const osList = ["Linux 4.19", "Windows 10", "Ubuntu 20.04", "CentOS 7", "Debian 11", "FreeBSD 13"];
  return random(osList);
}

/**
 * Generate a random status
 * @returns {string} Random status
 */
function generateRandomStatus() {
  const statusList = ["ACTIVE", "VULNERABLE", "COMPROMISED", "ACTIVE", "ACTIVE"];
  return random(statusList);
}

/**
 * Generate random ports
 * @returns {Array} Array of random port numbers
 */
function generateRandomPorts() {
  const ports = [];
  const numPorts = floor(random(1, 5));
  for (let i = 0; i < numPorts; i++) {
    ports.push(floor(random(1, 65535)));
  }
  return ports;
}

/**
 * Generate a random country code
 * @returns {string} Random country code
 */
function generateRandomCountry() {
  const countries = ["US", "CN", "RU", "DE", "JP", "GB", "FR", "CA"];
  return random(countries);
}

/**
 * Generate a random version string
 * @returns {string} Random version
 */
function generateRandomVersion() {
  const versions = ["1.2.3", "2.1.0", "3.0.1", "1.0.0", "4.2.1", "2.3.4"];
  return random(versions);
}

/**
 * Generate a random banner
 * @returns {string} Random banner
 */
function generateRandomBanner() {
  const banners = ["SSH-2.0-OpenSSH_8.2p1", "HTTP/1.1 200 OK", "220 smtp.example.com", "MySQL 5.7.33"];
  return random(banners);
}

/**
 * Generate a random terminal command
 * @returns {string} Random terminal command
 */
function generateRandomTerminalCommand() {
  const commands = [
    "nmap -sS -p- 192.168.1.0/24",
    "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe",
    "sqlmap -u http://target.com/login.php --dbs",
    "hydra -l admin -P wordlist.txt ssh://192.168.1.1",
    "aircrack-ng capture.cap -w wordlist.txt",
    "metasploit > use exploit/windows/smb/ms17_010_eternalblue",
    "wireshark -i eth0 -k",
    "john --wordlist=rockyou.txt hash.txt",
    "dirb http://target.com /usr/share/dirb/wordlists/common.txt",
    "nikto -h http://target.com"
  ];
  return "root@nexus:~# " + random(commands);
}

// ============================================================================
// INITIALIZATION FUNCTIONS
// ============================================================================

/**
 * Initialize network nodes
 */
function initializeNodes() {
  for (let i = 0; i < 15; i++) {
    NetworkData.nodes.push({
      x: random(0.1, 0.9),
      y: random(0.2, 0.8),
      ip: generateRandomIP(),
      os: generateRandomOS(),
      status: generateRandomStatus(),
      ports: generateRandomPorts(),
      lastSeen: floor(random(1, 60))
    });
  }
}

/**
 * Initialize network hops
 */
function initializeHops() {
  for (let i = 0; i < 8; i++) {
    NetworkData.hops.push({
      x: random(50, 200),
      y: random(50, 200),
      ip: generateRandomIP(),
      country: generateRandomCountry(),
      latency: random(10, 200)
    });
  }
}

/**
 * Initialize scan results
 */
function initializeScanResults() {
  const services = ["SSH", "HTTP", "HTTPS", "FTP", "SMTP", "DNS", "RDP", "VNC", "MySQL", "PostgreSQL"];
  for (let i = 0; i < 20; i++) {
    PanelData.scanResults.push({
      ip: generateRandomIP(),
      port: floor(random(1, 65535)),
      service: random(services),
      version: generateRandomVersion(),
      banner: generateRandomBanner()
    });
  }
}

/**
 * Initialize exploit status
 */
function initializeExploitStatus() {
  const exploits = ["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708", "CVE-2018-7600"];
  for (let i = 0; i < 10; i++) {
    PanelData.exploitStatus.push({
      exploit: random(exploits),
      target: generateRandomIP(),
      status: random(["PENDING", "RUNNING", "SUCCESS", "FAILED"]),
      progress: random(0, 100),
      startTime: random() < 0.3 ? AppState.currentTime - random(1000, 5000) : null,
      estimatedDuration: random(2000, 8000)
    });
  }
}

/**
 * Initialize network traffic
 */
function initializeNetworkTraffic() {
  for (let i = 0; i < 50; i++) {
    NetworkData.networkTraffic.push({
      src: generateRandomIP(),
      dst: generateRandomIP(),
      protocol: random(["TCP", "UDP", "ICMP"]),
      port: floor(random(1, 65535)),
      size: random(64, 1500),
      timestamp: random(0, AppState.currentTime)
    });
  }
}

/**
 * Initialize attack sequence
 */
function initializeAttackSequence() {
  AttackSequence.targets = NetworkData.nodes.map(n => n.ip);
  AttackSequence.currentPhase = AttackConfig.PHASES.TARGET_SELECTION;
  AttackSequence.phaseTimer = 0;
  AttackSequence.attackInProgress = true;
  AttackSequence.currentTargetIndex = 0;
  AttackSequence.currentTarget = AttackSequence.targets[0];
}

/**
 * Restart attack sequence with next target
 */
function restartAttackSequence() {
  AttackSequence.currentPhase = AttackConfig.PHASES.TARGET_SELECTION;
  AttackSequence.phaseTimer = 0;
  AttackSequence.attackInProgress = true;
  AttackSequence.currentTargetIndex = (AttackSequence.currentTargetIndex + 1) % AttackSequence.targets.length;
  AttackSequence.currentTarget = AttackSequence.targets[AttackSequence.currentTargetIndex];
}

// ============================================================================
// ATTACK SEQUENCE MANAGEMENT
// ============================================================================

/**
 * Update attack sequence state
 */
function updateAttackSequence() {
  if (!AttackSequence.attackInProgress) return;

  AttackSequence.phaseTimer += AppState.deltaTime;

  if (AttackSequence.phaseTimer >= AttackConfig.PHASE_DURATION) {
    AttackSequence.phaseTimer = 0;
    AttackSequence.currentPhase++;

    if (AttackSequence.currentPhase > AttackConfig.PHASES.COMPLETE) {
      setTimeout(() => {
        restartAttackSequence();
      }, 2000);
      return;
    }

    handlePhaseTransition();
  }
}

/**
 * Handle phase transitions
 */
function handlePhaseTransition() {
  switch (AttackSequence.currentPhase) {
    case AttackConfig.PHASES.TARGET_SELECTION:
      AttackSequence.currentTarget = AttackSequence.targets[AttackSequence.currentTargetIndex];
      SharedAttackData.currentTarget = AttackSequence.currentTarget;
      SharedAttackData.lastUpdate = AppState.currentTime;
      break;
      
    case AttackConfig.PHASES.TERMINAL_COMMAND:
      PanelData.terminalLog.push(generateRandomTerminalCommand());
      if (PanelData.terminalLog.length > 15) PanelData.terminalLog.shift();
      break;
      
    case AttackConfig.PHASES.NETWORK_HIGHLIGHT:
      SharedAttackData.networkChanges.push({
        target: AttackSequence.currentTarget,
        type: "TARGET_ACQUIRED",
        timestamp: AppState.currentTime
      });
      break;
      
    case AttackConfig.PHASES.VULNERABILITY_SCAN:
      SharedAttackData.discoveredVulnerabilities.push({
        target: AttackSequence.currentTarget,
        vulnerability: random(["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472"]),
        timestamp: AppState.currentTime
      });
      break;
      
    case AttackConfig.PHASES.EXPLOIT_EXECUTION:
      SharedAttackData.successfulExploits.push({
        target: AttackSequence.currentTarget,
        exploit: random(["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472"]),
        timestamp: AppState.currentTime
      });
      break;
  }
}

// ============================================================================
// MAIN APPLICATION FUNCTIONS
// ============================================================================

/**
 * Setup function - called once at startup
 */
function setup() {
  createCanvas(windowWidth, windowHeight);
  textFont("Courier");
  
  initializeNodes();
  initializeHops();
  initializeScanResults();
  initializeExploitStatus();
  initializeNetworkTraffic();
  initializeAttackSequence();
}

/**
 * Draw function - called every frame
 */
function draw() {
  background(0);
  
  // Update application state
  AppState.currentTime = millis();
  AppState.deltaTime = AppState.currentTime - AppState.lastTime;
  AppState.lastTime = AppState.currentTime;
  AppState.frameCount = frameCount;
  
  // Update attack sequence
  updateAttackSequence();
  
  // Calculate layout
  const layout = calculateLayout();
  
  // Draw interface panels
  drawInterfacePanels(layout);
  
  // Draw status bar
  drawStatusBar();
}

/**
 * Calculate interface layout
 * @returns {Object} Layout dimensions
 */
function calculateLayout() {
  const margin = 15;
  const statusBarHeight = 40;
  const availableHeight = height - statusBarHeight - 3 * margin;
  const panelWidth = (width - 3 * margin) / 2;
  const panelHeight = availableHeight / 2;
  
  return {
    margin,
    statusBarHeight,
    panelWidth,
    panelHeight,
    networkMap: { x: margin, y: margin, w: panelWidth, h: panelHeight },
    terminal: { x: margin + panelWidth + margin, y: margin, w: panelWidth, h: panelHeight },
    vulnerabilityScanner: { x: margin, y: margin + panelHeight + margin, w: panelWidth, h: panelHeight },
    exploitFramework: { x: margin + panelWidth + margin, y: margin + panelHeight + margin, w: panelWidth, h: panelHeight }
  };
}

/**
 * Draw all interface panels
 * @param {Object} layout - Layout dimensions
 */
function drawInterfacePanels(layout) {
  drawNetworkMap(layout.networkMap.x, layout.networkMap.y, layout.networkMap.w, layout.networkMap.h);
  drawTerminal(layout.terminal.x, layout.terminal.y, layout.terminal.w, layout.terminal.h);
  drawVulnerabilityScanner(layout.vulnerabilityScanner.x, layout.vulnerabilityScanner.y, layout.vulnerabilityScanner.w, layout.vulnerabilityScanner.h);
  drawExploitFramework(layout.exploitFramework.x, layout.exploitFramework.y, layout.exploitFramework.w, layout.exploitFramework.h);
}

/**
 * Draw network topology map
 * @param {number} x - X position
 * @param {number} y - Y position
 * @param {number} w - Width
 * @param {number} h - Height
 */
function drawNetworkMap(x, y, w, h) {
  push();
  translate(x, y);
  
  drawNetworkMapBackground(w, h);
  drawNetworkMapHeader(w, h);
  drawNetworkMapNodes(w, h);
  drawNetworkMapStatus(w, h);
  
  pop();
}

/**
 * Draw network map background
 * @param {number} w - Width
 * @param {number} h - Height
 */
function drawNetworkMapBackground(w, h) {
  fill(0, 20, 0);
  rect(0, 0, w, h);
  stroke(0, 100, 0);
  strokeWeight(1);
  noFill();
  rect(0, 0, w, h);
}

/**
 * Draw network map header
 * @param {number} w - Width
 * @param {number} h - Height
 */
function drawNetworkMapHeader(w, h) {
  // Title
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(18));
  textAlign(CENTER);
  text("NETWORK TOPOLOGY", w/2, 25);
  textAlign(LEFT);
  
  // Subtitle
  fill(0, 150, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text(`ACTIVE NODES: ${NetworkData.nodes.length} | SCAN STATUS: ACTIVE`, w/2, 40);
  textAlign(LEFT);
  
  // Network status indicator
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(RIGHT);
  text("NETWORK STATUS: ONLINE", w - 15, 25);
  textAlign(LEFT);
  
  // Status summary
  const activeCount = NetworkData.nodes.filter(n => n.status === "ACTIVE").length;
  const vulnerableCount = NetworkData.nodes.filter(n => n.status === "VULNERABLE").length;
  const compromisedCount = NetworkData.nodes.filter(n => n.status === "COMPROMISED").length;
  
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(LEFT);
  text(`ACTIVE: ${activeCount} | VULN: ${vulnerableCount} | COMP: ${compromisedCount}`, 15, 25);
}

/**
 * Draw network map nodes
 * @param {number} w - Width
 * @param {number} h - Height
 */
function drawNetworkMapNodes(w, h) {
  const margin = 100;
  
  for (let i = 0; i < NetworkData.nodes.length; i++) {
    const node = NetworkData.nodes[i];
    const nodeX = node.x * w;
    const nodeY = node.y * h;
    
    // Skip nodes outside panel bounds
    if (nodeX < margin || nodeX > w - margin || nodeY < margin || nodeY > h - margin) {
      continue;
    }
    
    drawNetworkNode(node, nodeX, nodeY, w, h, margin, i);
  }
}

/**
 * Draw individual network node
 * @param {Object} node - Node data
 * @param {number} nodeX - Node X position
 * @param {number} nodeY - Node Y position
 * @param {number} w - Panel width
 * @param {number} h - Panel height
 * @param {number} margin - Panel margin
 * @param {number} nodeIndex - Node index
 */
function drawNetworkNode(node, nodeX, nodeY, w, h, margin, nodeIndex) {
  const nodeColor = getNodeColor(node.status);
  
  // Draw target highlighting
  drawTargetHighlighting(node, nodeX, nodeY);
  
  // Draw attack progression
  drawAttackProgression(node, nodeX, nodeY);
  
  // Draw node
  fill(nodeColor);
  noStroke();
  ellipse(nodeX, nodeY, 6, 6);
  
  // Draw connections
  drawNodeConnections(node, nodeX, nodeY, w, h, margin, nodeIndex);
  
  // Draw node labels
  drawNodeLabels(node, nodeX, nodeY);
}

/**
 * Get node color based on status
 * @param {string} status - Node status
 * @returns {color} Node color
 */
function getNodeColor(status) {
  switch (status) {
    case "ACTIVE": return color(0, 255, 0);
    case "VULNERABLE": return color(255, 165, 0);
    case "COMPROMISED": return color(255, 0, 0);
    default: return color(0, 255, 0);
  }
}

/**
 * Draw target highlighting effects
 * @param {Object} node - Node data
 * @param {number} nodeX - Node X position
 * @param {number} nodeY - Node Y position
 */
function drawTargetHighlighting(node, nodeX, nodeY) {
  if (!AttackSequence.attackInProgress || !AttackSequence.currentTarget || node.ip !== AttackSequence.currentTarget) {
    return;
  }
  
  if (AttackSequence.currentPhase >= AttackConfig.PHASES.TARGET_SELECTION) {
    const pulseSize = 6 + sin(AppState.frameCount * 0.1) * 4;
    
    if (AttackSequence.currentPhase === AttackConfig.PHASES.TARGET_SELECTION) {
      // Scanning effect
      fill(255, 255, 0, 150);
      ellipse(nodeX, nodeY, pulseSize * 2, pulseSize * 2);
      fill(255, 255, 0);
      ellipse(nodeX, nodeY, pulseSize, pulseSize);
    } else if (AttackSequence.currentPhase >= AttackConfig.PHASES.NETWORK_HIGHLIGHT) {
      // Locked target effect
      fill(255, 0, 0);
      ellipse(nodeX, nodeY, pulseSize, pulseSize);
      
      // Draw attack indicator
      fill(255, 0, 0);
      textSize(getResponsiveTextSize(10));
      textAlign(CENTER);
      text("TARGET", nodeX, nodeY - 20);
      textAlign(LEFT);
      
      // Draw crosshair effect
      stroke(255, 0, 0);
      strokeWeight(1);
      line(nodeX - 15, nodeY, nodeX + 15, nodeY);
      line(nodeX, nodeY - 15, nodeX, nodeY + 15);
      noStroke();
    }
  }
}

/**
 * Draw attack progression indicators
 * @param {Object} node - Node data
 * @param {number} nodeX - Node X position
 * @param {number} nodeY - Node Y position
 */
function drawAttackProgression(node, nodeX, nodeY) {
  if (!AttackSequence.attackInProgress) return;
  
  const targetIndex = AttackSequence.targets.indexOf(node.ip);
  if (targetIndex === -1) return;
  
  if (targetIndex < AttackSequence.currentTargetIndex) {
    // Already processed nodes
    fill(0, 100, 0, 100);
    ellipse(nodeX, nodeY, 8, 8);
  } else if (targetIndex > AttackSequence.currentTargetIndex) {
    // Upcoming targets
    fill(100, 100, 100, 50);
    ellipse(nodeX, nodeY, 4, 4);
  }
}

/**
 * Draw node connections
 * @param {Object} node - Node data
 * @param {number} nodeX - Node X position
 * @param {number} nodeY - Node Y position
 * @param {number} w - Panel width
 * @param {number} h - Panel height
 * @param {number} margin - Panel margin
 * @param {number} nodeIndex - Node index
 */
function drawNodeConnections(node, nodeX, nodeY, w, h, margin, nodeIndex) {
  stroke(0, 100, 0);
  strokeWeight(1);
  
  for (let j = 0; j < 3; j++) {
    const target = NetworkData.nodes[(nodeIndex + j + 1) % NetworkData.nodes.length];
    const targetX = target.x * w;
    const targetY = target.y * h;
    
    // Only draw connection if target is also within bounds
    if (targetX >= margin && targetX <= w - margin && targetY >= margin && targetY <= h - margin) {
      line(nodeX, nodeY, targetX, targetY);
    }
  }
}

/**
 * Draw node labels
 * @param {Object} node - Node data
 * @param {number} nodeX - Node X position
 * @param {number} nodeY - Node Y position
 */
function drawNodeLabels(node, nodeX, nodeY) {
  // IP label
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(LEFT);
  const ipText = truncateText(node.ip, 80, 8);
  text(ipText, nodeX + 12, nodeY - 4);
  
  // OS label
  fill(0, 200, 0);
  textSize(getResponsiveTextSize(8));
  const osText = truncateText(node.os, 60, 6);
  text(osText, nodeX + 12, nodeY + 8);
}

/**
 * Draw network map status and attack progress
 * @param {number} w - Width
 * @param {number} h - Height
 */
function drawNetworkMapStatus(w, h) {
  // Attack sequence progress indicator
  if (AttackSequence.attackInProgress) {
    const phaseProgress = (AttackSequence.phaseTimer / AttackConfig.PHASE_DURATION) * 100;
    const phaseNames = AttackConfig.PHASE_NAMES;
    
    // Attack status indicator
    fill(255, 0, 0);
    textSize(getResponsiveTextSize(10));
    textAlign(RIGHT);
    text("ATTACK IN PROGRESS", w - 15, 40);
    textAlign(LEFT);
    
    // Phase indicator
    fill(255, 255, 0);
    textSize(getResponsiveTextSize(10));
    textAlign(LEFT);
    text(`PHASE: ${phaseNames[AttackSequence.currentPhase]}`, 15, h - 25);
    
    // Progress bar
    fill(0, 50, 0);
    rect(15, h - 15, 200, 6);
    fill(255, 255, 0);
    rect(15, h - 15, 200 * phaseProgress / 100, 6);
    
    // Progress percentage
    fill(255, 255, 0);
    textSize(getResponsiveTextSize(8));
    text(`${floor(phaseProgress)}%`, 220, h - 10);
    
    // Target information panel
    if (AttackSequence.currentTarget) {
      drawTargetInfoPanel(w, h);
    }
  }
}

/**
 * Draw target information panel
 * @param {number} w - Width
 * @param {number} h - Height
 */
function drawTargetInfoPanel(w, h) {
  fill(0, 20, 0);
  stroke(255, 0, 0);
  strokeWeight(1);
  rect(w/2 - 120, h - 60, 240, 50);
  
  fill(255, 0, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text("CURRENT TARGET", w/2, h - 45);
  
  fill(255, 255, 0);
  textSize(getResponsiveTextSize(12));
  text(AttackSequence.currentTarget, w/2, h - 30);
  
  // Find target node info
  const targetNode = NetworkData.nodes.find(n => n.ip === AttackSequence.currentTarget);
  if (targetNode) {
    fill(0, 255, 0);
    textSize(getResponsiveTextSize(8));
    text(`${targetNode.os} | ${targetNode.status}`, w/2, h - 15);
  }
  textAlign(LEFT);
}



function drawTerminal(x, y, w, h) {
  push();
  translate(x, y);
  
  // Background
  fill(0, 20, 0);
  rect(0, 0, w, h);
  stroke(0, 100, 0);
  strokeWeight(1);
  noFill();
  rect(0, 0, w, h);
  
  // Title with better spacing
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(18));
  textAlign(CENTER);
  text("TERMINAL SESSION", w/2, 30);
  textAlign(LEFT);
  
  // Session info
  fill(0, 150, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text("SESSION: " + floor(AppState.currentTime/1000) + "s | COMMANDS: " + PanelData.terminalLog.length, w/2, 45);
  textAlign(LEFT);
  
  // Terminal content
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(12));
  let startY = 75;
  let lineHeight = 18;
  
  // Add realistic terminal output
  if (frameCount % 30 === 0 && !AttackSequence.attackInProgress) {
    PanelData.terminalLog.push(generateRandomTerminalCommand());
    if (PanelData.terminalLog.length > 15) PanelData.terminalLog.shift();
  }
  
  // Show attack sequence commands with cross-panel coordination
  if (AttackSequence.attackInProgress && AttackSequence.currentPhase === AttackConfig.PHASES.TERMINAL_COMMAND) {
    let attackCommands = [
      "nmap -sS -p- " + AttackSequence.currentTarget,
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe",
      "metasploit > use exploit/windows/smb/ms17_010_eternalblue",
      "metasploit > set RHOSTS " + AttackSequence.currentTarget,
      "metasploit > exploit",
      "hydra -l admin -P wordlist.txt ssh://" + AttackSequence.currentTarget,
      "sqlmap -u http://" + AttackSequence.currentTarget + "/login.php --dbs"
    ];
    
    if (PanelData.terminalLog.length === 0 || !PanelData.terminalLog[PanelData.terminalLog.length - 1].includes(AttackSequence.currentTarget)) {
      PanelData.terminalLog.push("root@nexus:~# " + random(attackCommands));
      if (PanelData.terminalLog.length > 15) PanelData.terminalLog.shift();
    }
  }
  
  // Cross-panel coordination: Show commands that affect other panels
  if (AttackSequence.attackInProgress && AttackSequence.currentTarget) {
    let phaseCommands = {
      [AttackConfig.PHASES.TARGET_SELECTION]: [
        "ping -c 4 " + AttackSequence.currentTarget,
        "arp -a | grep " + AttackSequence.currentTarget,
        "nslookup " + AttackSequence.currentTarget
      ],
      [AttackConfig.PHASES.VULNERABILITY_SCAN]: [
        "nmap -sV -sC " + AttackSequence.currentTarget,
        "nikto -h http://" + AttackSequence.currentTarget,
        "dirb http://" + AttackSequence.currentTarget + " /usr/share/dirb/wordlists/common.txt"
      ],
      [AttackConfig.PHASES.EXPLOIT_EXECUTION]: [
        "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS " + AttackSequence.currentTarget + "; exploit'",
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://" + AttackSequence.currentTarget,
        "sqlmap -u http://" + AttackSequence.currentTarget + "/login.php --dbs --batch"
      ]
    };
    
    if (phaseCommands[AttackSequence.currentPhase] && frameCount % 45 === 0) {
      let command = "root@nexus:~# " + random(phaseCommands[AttackSequence.currentPhase]);
      if (!PanelData.terminalLog.includes(command)) {
        PanelData.terminalLog.push(command);
        if (PanelData.terminalLog.length > 15) PanelData.terminalLog.shift();
      }
    }
  }
  
  for (let i = 0; i < PanelData.terminalLog.length; i++) {
    let command = PanelData.terminalLog[i];
    // Truncate long commands to fit panel width
    if (textWidth(command) > w - 20) {
      command = command.substring(0, Math.floor((w - 20) / 8)) + "...";
    }
    text(command, 10, startY + i * lineHeight);
  }
  
  // Cursor
  if (frameCount % 60 < 30) {
    fill(0, 255, 0);
    text("█", 10 + textWidth(PanelData.terminalLog[PanelData.terminalLog.length - 1] || ""), startY + (PanelData.terminalLog.length - 1) * lineHeight);
  }
  
  pop();
}

function drawVulnerabilityScanner(x, y, w, h) {
  push();
  translate(x, y);
  
  // Background
  fill(0, 20, 0);
  rect(0, 0, w, h);
  stroke(0, 100, 0);
  strokeWeight(1);
  noFill();
  rect(0, 0, w, h);
  
  // Title with better spacing
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(18));
  textAlign(CENTER);
  text("VULNERABILITY SCANNER", w/2, 30);
  textAlign(LEFT);
  
  // Scanner status
  fill(0, 150, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text("SCAN RANGE: 1-1024 | PROTOCOLS: TCP/UDP", w/2, 45);
  textAlign(LEFT);
  
  // Scan results
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(11));
  let startY = 75;
  let lineHeight = 16;
  
  for (let i = 0; i < min(8, PanelData.scanResults.length); i++) {
    let result = PanelData.scanResults[i];
    let yPos = startY + i * lineHeight;
    
    // Better distributed column spacing across panel width
    let col1X = 15;                    // IP:Port column (left)
    let col2X = w * 0.35;              // Service column (35% of panel width)
    let col3X = w * 0.65;              // Banner column (65% of panel width)
    
    // IP and port with truncation
    fill(0, 255, 0);
    textAlign(LEFT);
    let ipPort = result.ip + ":" + result.port;
    if (textWidth(ipPort) > w * 0.25) {
      ipPort = result.ip.substring(0, 6) + "..:" + result.port;
    }
    text(ipPort, col1X, yPos);
    
    // Service with truncation
    fill(255, 165, 0);
    let service = result.service;
    if (textWidth(service) > w * 0.25) {
      service = service.substring(0, 6) + "..";
    }
    text(service, col2X, yPos);
    
    // Version with truncation
    fill(0, 255, 0);
    let version = result.version;
    if (textWidth(version) > w * 0.15) {
      version = version.substring(0, 8) + "..";
    }
    text(version, col2X + w * 0.15, yPos);
    
    // Banner with truncation
    fill(100, 100, 100);
    let banner = result.banner;
    if (textWidth(banner) > w * 0.3) {
      banner = banner.substring(0, 15) + "...";
    }
    text(banner, col3X, yPos);
  }
  
  // Current scan target
  let scanProgress = (frameCount / 10) % 100;
  let currentTarget = "192.168.1." + floor((frameCount / 10) % 255);
  let currentPort = floor(random(1, 65535));
  
  // Show coordinated scanning during attack sequence
  if (AttackSequence.attackInProgress && AttackSequence.currentPhase === AttackConfig.PHASES.VULNERABILITY_SCAN && AttackSequence.currentTarget) {
    currentTarget = AttackSequence.currentTarget;
    scanProgress = (AttackSequence.phaseTimer / AttackConfig.PHASE_DURATION) * 100;
    
    // Add scan results for current target
    if (frameCount % 15 === 0) {
      let newResult = {
        ip: currentTarget,
        port: floor(random(1, 65535)),
        service: random(["SSH", "HTTP", "HTTPS", "FTP", "SMTP", "DNS", "RDP", "VNC", "MySQL", "PostgreSQL"]),
        version: generateRandomVersion(),
        banner: generateRandomBanner()
      };
      PanelData.scanResults.unshift(newResult);
      if (PanelData.scanResults.length > 20) PanelData.scanResults.pop();
    }
  }
  
  // Focus scanner on current target node
  if (AttackSequence.attackInProgress && AttackSequence.currentTarget) {
    let targetNode = NetworkData.nodes.find(n => n.ip === AttackSequence.currentTarget);
    if (targetNode) {
      // Show target-specific scan results
      if (frameCount % 20 === 0) {
        let targetServices = {
          "Linux 4.19": ["SSH", "HTTP", "HTTPS", "MySQL"],
          "Windows 10": ["RDP", "SMB", "HTTP", "VNC"],
          "Ubuntu 20.04": ["SSH", "HTTP", "HTTPS", "PostgreSQL"],
          "CentOS 7": ["SSH", "HTTP", "FTP", "MySQL"],
          "Debian 11": ["SSH", "HTTP", "DNS", "PostgreSQL"],
          "FreeBSD 13": ["SSH", "HTTP", "FTP", "VNC"]
        };
        
        let osServices = targetServices[targetNode.os] || ["SSH", "HTTP"];
        let service = random(osServices);
        let port = service === "SSH" ? 22 : service === "HTTP" ? 80 : service === "HTTPS" ? 443 : floor(random(1, 65535));
        
        let newResult = {
          ip: AttackSequence.currentTarget,
          port: port,
          service: service,
          version: targetNode.os,
          banner: service + " service on " + targetNode.os
        };
        PanelData.scanResults.unshift(newResult);
        if (PanelData.scanResults.length > 20) PanelData.scanResults.pop();
      }
    }
  }
  
  // Cross-panel coordination: Show scan results that match exploit targets
  if (AttackSequence.attackInProgress && AttackSequence.currentTarget) {
    let targetExploits = PanelData.exploitStatus.filter(e => e.target === AttackSequence.currentTarget);
    if (targetExploits.length > 0 && frameCount % 20 === 0) {
      let exploit = targetExploits[0];
      let vulnerableServices = {
        "CVE-2021-44228": { service: "HTTP", port: 8080, version: "Log4j 2.14.1" },
        "CVE-2021-34527": { service: "RDP", port: 3389, version: "Windows 10" },
        "CVE-2020-1472": { service: "SMB", port: 445, version: "Windows Server" },
        "CVE-2019-0708": { service: "RDP", port: 3389, version: "Windows 7" },
        "CVE-2018-7600": { service: "HTTP", port: 80, version: "Drupal 7.58" }
      };
      
      if (vulnerableServices[exploit.exploit]) {
        let vulnService = vulnerableServices[exploit.exploit];
        let newResult = {
          ip: AttackSequence.currentTarget,
          port: vulnService.port,
          service: vulnService.service,
          version: vulnService.version,
          banner: "VULNERABLE: " + exploit.exploit
        };
        PanelData.scanResults.unshift(newResult);
        if (PanelData.scanResults.length > 20) PanelData.scanResults.pop();
      }
    }
  }
  
  // Status and current target with better layout
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(12));
  textAlign(LEFT);
  
  // Progress info
  text("SCANNING: " + floor(scanProgress) + "% | TARGET: " + currentTarget + ":" + currentPort, 15, h - 55);
  text("FOUND: " + PanelData.scanResults.length + " SERVICES | PORTS: 1-1024", 15, h - 35);
  
  // Progress bar below the text
  fill(0, 50, 0);
  rect(15, h - 25, w - 30, 12);
  fill(0, 255, 0);
  rect(15, h - 25, (w - 30) * scanProgress / 100, 12);
  
  pop();
}

function drawExploitFramework(x, y, w, h) {
  push();
  translate(x, y);
  
  // Background with dynamic effect
  fill(0, 20, 0);
  rect(0, 0, w, h);
  stroke(0, 100, 0);
  strokeWeight(1);
  noFill();
  rect(0, 0, w, h);
  
  // Animated background pattern for active exploits
  let runningExploits = PanelData.exploitStatus.filter(e => e.status === "RUNNING").length;
  if (runningExploits > 0) {
    for (let i = 0; i < runningExploits * 2; i++) {
      let xPos = (frameCount * 0.5 + i * 50) % (w + 100) - 50;
      let yPos = 20 + (i * 30) % (h - 40);
      fill(0, 255, 0, 20);
      noStroke();
      ellipse(xPos, yPos, 4, 4);
    }
  }
  
  // Title with pulsing effect when exploits are running
  if (runningExploits > 0) {
    let pulseIntensity = sin(frameCount * 0.1) * 50;
    fill(0, 255 + pulseIntensity, 0);
  } else {
    fill(0, 255, 0);
  }
  textSize(getResponsiveTextSize(18));
  textAlign(CENTER);
  text("EXPLOIT FRAMEWORK", w/2, 30);
  textAlign(LEFT);
  
  // Framework status with dynamic counter
  fill(0, 150, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text("EXPLOITS: " + PanelData.exploitStatus.length + " | ACTIVE: " + runningExploits + " | SUCCESS: " + PanelData.exploitStatus.filter(e => e.status === "SUCCESS").length, w/2, 45);
  textAlign(LEFT);
  
  // Exploit status
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(11));
  let startY = 75;
  let lineHeight = 18;
  
  // Show coordinated exploitation during attack sequence
  if (AttackSequence.attackInProgress && AttackSequence.currentPhase === AttackConfig.PHASES.EXPLOIT_EXECUTION && AttackSequence.currentTarget) {
    // Add new exploit for current target
    if (frameCount % 30 === 0) {
      let newExploit = {
        exploit: random(["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708", "CVE-2018-7600"]),
        target: AttackSequence.currentTarget,
        status: "RUNNING",
        progress: (AttackSequence.phaseTimer / AttackConfig.PHASE_DURATION) * 100,
        startTime: AppState.currentTime,
        estimatedDuration: random(2000, 8000)
      };
      PanelData.exploitStatus.unshift(newExploit);
      if (PanelData.exploitStatus.length > 10) PanelData.exploitStatus.pop();
    }
  }
  
  // Focus exploits on current target node
  if (AttackSequence.attackInProgress && AttackSequence.currentTarget) {
    let targetNode = NetworkData.nodes.find(n => n.ip === AttackSequence.currentTarget);
    if (targetNode && frameCount % 45 === 0) {
      // OS-specific exploits
      let osExploits = {
        "Linux 4.19": ["CVE-2021-44228", "CVE-2021-34527", "CVE-2018-7600"],
        "Windows 10": ["CVE-2020-1472", "CVE-2019-0708", "CVE-2021-34527"],
        "Ubuntu 20.04": ["CVE-2021-44228", "CVE-2018-7600"],
        "CentOS 7": ["CVE-2021-44228", "CVE-2018-7600"],
        "Debian 11": ["CVE-2021-44228", "CVE-2018-7600"],
        "FreeBSD 13": ["CVE-2021-44228", "CVE-2018-7600"]
      };
      
      let availableExploits = osExploits[targetNode.os] || ["CVE-2021-44228"];
      let exploit = random(availableExploits);
      
      let newExploit = {
        exploit: exploit,
        target: AttackSequence.currentTarget,
        status: "RUNNING",
        progress: 0,
        startTime: AppState.currentTime,
        estimatedDuration: random(3000, 10000)
      };
      PanelData.exploitStatus.unshift(newExploit);
      if (PanelData.exploitStatus.length > 10) PanelData.exploitStatus.pop();
    }
  }
  
  // Cross-panel coordination: Update node status based on exploit results
  if (AttackSequence.attackInProgress && AttackSequence.currentTarget) {
    let targetNode = NetworkData.nodes.find(n => n.ip === AttackSequence.currentTarget);
    if (targetNode) {
      let successfulExploits = PanelData.exploitStatus.filter(e => e.target === AttackSequence.currentTarget && e.status === "SUCCESS").length;
      if (successfulExploits > 0 && targetNode.status !== "COMPROMISED") {
        targetNode.status = "COMPROMISED";
      } else if (AttackSequence.currentPhase >= AttackConfig.PHASES.VULNERABILITY_SCAN && targetNode.status === "ACTIVE") {
        targetNode.status = "VULNERABLE";
      }
    }
  }
  
  // Update exploit progress dynamically
  for (let exploit of PanelData.exploitStatus) {
    if (exploit.status === "RUNNING" && exploit.startTime) {
      let elapsed = AppState.currentTime - exploit.startTime;
      exploit.progress = min((elapsed / exploit.estimatedDuration) * 100, 100);
      
      // Randomly complete exploits
      if (exploit.progress >= 100 && random() < 0.1) {
        exploit.status = random() < 0.7 ? "SUCCESS" : "FAILED";
        exploit.progress = 100;
      }
    }
  }
  
  for (let i = 0; i < min(8, PanelData.exploitStatus.length); i++) {
    let exploit = PanelData.exploitStatus[i];
    let yPos = startY + i * lineHeight;
    
    // Better distributed column spacing across panel width
    let col1X = 15;                    // Exploit name column (left)
    let col2X = w * 0.25;              // Target column (25% of panel width)
    let col3X = w * 0.50;              // Status column (50% of panel width)
    let col4X = w * 0.75;              // Progress bar column (75% of panel width)
    
    // Exploit name with truncation
    fill(0, 255, 0);
    textAlign(LEFT);
    let exploitName = exploit.exploit;
    if (textWidth(exploitName) > w * 0.2) {
      exploitName = exploitName.substring(0, 10) + "..";
    }
    text(exploitName, col1X, yPos);
    
    // Target with truncation
    fill(255, 165, 0);
    let target = exploit.target;
    if (textWidth(target) > w * 0.2) {
      target = target.substring(0, 8) + "..";
    }
    text(target, col2X, yPos);
    
    // Status with better alignment
    let statusColor = exploit.status === "SUCCESS" ? color(0, 255, 0) :
                     exploit.status === "RUNNING" ? color(255, 165, 0) :
                     exploit.status === "FAILED" ? color(255, 0, 0) : color(100, 100, 100);
    fill(statusColor);
    text(exploit.status, col3X, yPos);
    
    // Progress bar with better positioning and animation
    if (exploit.status === "RUNNING") {
      fill(0, 50, 0);
      rect(col4X, yPos - 8, w * 0.2, 8);
      
      // Animated progress bar
      let progressColor = color(0, 255, 0);
      if (exploit.progress > 80) {
        progressColor = color(255, 255, 0); // Yellow for near completion
      }
      fill(progressColor);
      rect(col4X, yPos - 8, w * 0.2 * exploit.progress / 100, 8);
      
      // Progress percentage
      fill(255, 255, 255);
      textSize(getResponsiveTextSize(8));
      text(floor(exploit.progress) + "%", col4X + w * 0.2 + 5, yPos);
      
      // Pulsing effect for running exploits
      let pulseSize = 2 + sin(frameCount * 0.2) * 1;
      fill(255, 255, 0, 100);
      ellipse(col4X + w * 0.1, yPos - 4, pulseSize, pulseSize);
    } else if (exploit.status === "SUCCESS") {
      // Success indicator
      fill(0, 255, 0);
      textSize(getResponsiveTextSize(8));
      text("✓", col4X + w * 0.1, yPos);
    } else if (exploit.status === "FAILED") {
      // Failed indicator
      fill(255, 0, 0);
      textSize(getResponsiveTextSize(8));
      text("✗", col4X + w * 0.1, yPos);
    }
  }
  
  // Summary with better layout and dynamic effects
  let runningCount = PanelData.exploitStatus.filter(e => e.status === "RUNNING").length;
  let successCount = PanelData.exploitStatus.filter(e => e.status === "SUCCESS").length;
  let failedCount = PanelData.exploitStatus.filter(e => e.status === "FAILED").length;
  
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(12));
  textAlign(LEFT);
  
  // Summary header with pulsing effect when exploits are running
  if (runningCount > 0) {
    let pulseIntensity = sin(frameCount * 0.15) * 30;
    fill(0, 255 + pulseIntensity, 0);
  } else {
    fill(0, 255, 0);
  }
  text("EXPLOIT SUMMARY:", 15, h - 70);
  
  // Summary details with color coding and dynamic counters
  fill(255, 165, 0);
  text("• RUNNING: " + runningCount, 25, h - 50);
  fill(0, 255, 0);
  text("• SUCCESS: " + successCount, 25, h - 35);
  fill(255, 0, 0);
  text("• FAILED: " + failedCount, 25, h - 20);
  
  // Success rate indicator
  let totalExploits = PanelData.exploitStatus.length;
  let successRate = totalExploits > 0 ? (successCount / totalExploits) * 100 : 0;
  
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(10));
  text("SUCCESS RATE: " + floor(successRate) + "%", 15, h - 5);
  
  // Visual success rate bar
  fill(0, 50, 0);
  rect(w - 120, h - 15, 100, 8);
  fill(0, 255, 0);
  rect(w - 120, h - 15, 100 * successRate / 100, 8);
  
  pop();
}

function drawStatusBar() {
  push();
  fill(0, 50, 0);
  rect(0, height - 40, width, 40);
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(16));
  textAlign(LEFT);
  
  // Show attack status if in progress
  let statusText = "NEXUS-OS v3.2.1 | TARGET: 192.168.1.0/24 | USER: root | SESSION: " + floor(AppState.currentTime/1000);
  if (AttackSequence.attackInProgress) {
    let phaseNames = ["TARGET_SELECTION", "TERMINAL_COMMAND", "NETWORK_HIGHLIGHT", "VULNERABILITY_SCAN", "EXPLOIT_EXECUTION", "COMPLETE"];
    statusText = "NEXUS-OS v3.2.1 | ATTACK: " + phaseNames[AttackSequence.currentPhase] + " | TARGET: " + (AttackSequence.currentTarget || "NONE") + " | SESSION: " + floor(AppState.currentTime/1000);
  }
  
  text(statusText, 15, height - 15);
  textAlign(RIGHT);
  
  // More realistic system readings with much slower changes
  let cpuUsage = 18 + sin(frameCount * 0.001) * 5 + random(-1, 1); // 18-23% with very slow variation
  let memUsage = 52 + sin(frameCount * 0.0005) * 8 + random(-2, 2); // 52-60% with very slow variation
  let netSpeed = 16 + sin(frameCount * 0.002) * 4 + random(-0.5, 0.5); // 16-20 Mbps with very slow variation
  
  text("CPU: " + floor(cpuUsage) + "% | MEM: " + floor(memUsage) + "% | NET: " + floor(netSpeed) + " Mbps", width - 15, height - 15);
  pop();
}

function drawGlobalAttackIndicator() {
  push();
  
  // Semi-transparent overlay
  fill(0, 0, 0, 100);
  rect(0, 0, width, height);
  
  // Central attack status
  fill(255, 0, 0);
  textSize(getResponsiveTextSize(24));
  textAlign(CENTER);
  text("ATTACK IN PROGRESS", width/2, height/2 - 50);
  
  // Current target
  fill(255, 255, 0);
  textSize(getResponsiveTextSize(18));
  text("TARGET: " + (AttackSequence.currentTarget || "NONE"), width/2, height/2 - 20);
  
  // Phase indicator
  let phaseNames = ["TARGET_SELECTION", "TERMINAL_COMMAND", "NETWORK_HIGHLIGHT", "VULNERABILITY_SCAN", "EXPLOIT_EXECUTION"];
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(16));
  text("PHASE: " + phaseNames[AttackSequence.currentPhase], width/2, height/2 + 10);
  
  // Progress bar
  let phaseProgress = (AttackSequence.phaseTimer / AttackConfig.PHASE_DURATION) * 100;
  fill(0, 50, 0);
  rect(width/2 - 150, height/2 + 30, 300, 20);
  fill(255, 255, 0);
  rect(width/2 - 150, height/2 + 30, 300 * phaseProgress / 100, 20);
  
  // Progress percentage
  fill(255, 255, 255);
  textSize(getResponsiveTextSize(14));
  text(floor(phaseProgress) + "%", width/2, height/2 + 45);
  
  textAlign(LEFT);
  pop();
}
