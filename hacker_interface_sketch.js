
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

// Shared data for cross-panel coordination
let sharedAttackData = {
  currentTarget: null,
  discoveredVulnerabilities: [],
  successfulExploits: [],
  networkChanges: [],
  lastUpdate: 0
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
      progress: random(0, 100),
      startTime: random() < 0.3 ? currentTime - random(1000, 5000) : null,
      estimatedDuration: random(2000, 8000)
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
  // Use actual node IPs from the network topology
  attackSequence.targets = nodes.map(n => n.ip);
  attackSequence.currentPhase = PHASES.TARGET_SELECTION;
  attackSequence.phaseTimer = 0;
  attackSequence.attackInProgress = true;
  attackSequence.currentTargetIndex = 0;
  attackSequence.currentTarget = attackSequence.targets[0]; // Set initial target
}

function restartAttackSequence() {
  attackSequence.currentPhase = PHASES.TARGET_SELECTION;
  attackSequence.phaseTimer = 0;
  attackSequence.attackInProgress = true;
  attackSequence.currentTargetIndex = (attackSequence.currentTargetIndex + 1) % attackSequence.targets.length;
  attackSequence.currentTarget = attackSequence.targets[attackSequence.currentTargetIndex];
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
        attackSequence.currentTarget = attackSequence.targets[attackSequence.currentTargetIndex];
        sharedAttackData.currentTarget = attackSequence.currentTarget;
        sharedAttackData.lastUpdate = currentTime;
        console.log("Phase: Target Selection, Target: " + attackSequence.currentTarget);
        break;
      case PHASES.TERMINAL_COMMAND:
        terminalLog.push(generateTerminalCommand());
        if (terminalLog.length > 15) terminalLog.shift();
        console.log("Phase: Terminal Command, Command: " + terminalLog[terminalLog.length - 1]);
        break;
      case PHASES.NETWORK_HIGHLIGHT:
        // Update shared data for network changes
        sharedAttackData.networkChanges.push({
          target: attackSequence.currentTarget,
          type: "TARGET_ACQUIRED",
          timestamp: currentTime
        });
        console.log("Phase: Network Highlight");
        break;
      case PHASES.VULNERABILITY_SCAN:
        // Add discovered vulnerabilities to shared data
        sharedAttackData.discoveredVulnerabilities.push({
          target: attackSequence.currentTarget,
          vulnerability: random(["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472"]),
          timestamp: currentTime
        });
        console.log("Phase: Vulnerability Scan");
        break;
      case PHASES.EXPLOIT_EXECUTION:
        // Track successful exploits in shared data
        sharedAttackData.successfulExploits.push({
          target: attackSequence.currentTarget,
          exploit: random(["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472"]),
          timestamp: currentTime
        });
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
    
    // Show attack progression through nodes
    if (attackSequence.attackInProgress) {
      let targetIndex = attackSequence.targets.indexOf(n.ip);
      if (targetIndex !== -1) {
        // Show which nodes have been processed
        if (targetIndex < attackSequence.currentTargetIndex) {
          // Already processed nodes
          fill(0, 100, 0, 100);
          ellipse(nodeX, nodeY, 8, 8);
        } else if (targetIndex === attackSequence.currentTargetIndex) {
          // Current target (highlighted above)
        } else {
          // Upcoming targets
          fill(100, 100, 100, 50);
          ellipse(nodeX, nodeY, 4, 4);
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
    
    // Node info with better layout and truncation
    fill(0, 255, 0);
    textSize(getResponsiveTextSize(10));
    textAlign(LEFT);
    let ipText = n.ip;
    if (textWidth(ipText) > 80) {
      ipText = n.ip.substring(0, 8) + "..";
    }
    text(ipText, nodeX + 12, nodeY - 4);
    
    fill(0, 200, 0);
    textSize(getResponsiveTextSize(8));
    let osText = n.os;
    if (textWidth(osText) > 60) {
      osText = n.os.substring(0, 6) + "..";
    }
    text(osText, nodeX + 12, nodeY + 8);
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
  
  // Show attack sequence commands with cross-panel coordination
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
  
  // Cross-panel coordination: Show commands that affect other panels
  if (attackSequence.attackInProgress && attackSequence.currentTarget) {
    let phaseCommands = {
      [PHASES.TARGET_SELECTION]: [
        "ping -c 4 " + attackSequence.currentTarget,
        "arp -a | grep " + attackSequence.currentTarget,
        "nslookup " + attackSequence.currentTarget
      ],
      [PHASES.VULNERABILITY_SCAN]: [
        "nmap -sV -sC " + attackSequence.currentTarget,
        "nikto -h http://" + attackSequence.currentTarget,
        "dirb http://" + attackSequence.currentTarget + " /usr/share/dirb/wordlists/common.txt"
      ],
      [PHASES.EXPLOIT_EXECUTION]: [
        "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS " + attackSequence.currentTarget + "; exploit'",
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://" + attackSequence.currentTarget,
        "sqlmap -u http://" + attackSequence.currentTarget + "/login.php --dbs --batch"
      ]
    };
    
    if (phaseCommands[attackSequence.currentPhase] && frameCount % 45 === 0) {
      let command = "root@nexus:~# " + random(phaseCommands[attackSequence.currentPhase]);
      if (!terminalLog.includes(command)) {
        terminalLog.push(command);
        if (terminalLog.length > 15) terminalLog.shift();
      }
    }
  }
  
  for (let i = 0; i < terminalLog.length; i++) {
    let command = terminalLog[i];
    // Truncate long commands to fit panel width
    if (textWidth(command) > w - 20) {
      command = command.substring(0, Math.floor((w - 20) / 8)) + "...";
    }
    text(command, 10, startY + i * lineHeight);
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
    
    // Adjusted column widths to fit panel
    let col1X = 15;    // IP:Port column
    let col2X = 140;   // Service column (reduced)
    let col3X = 220;   // Banner column (reduced)
    
    // IP and port with truncation
    fill(0, 255, 0);
    textAlign(LEFT);
    let ipPort = result.ip + ":" + result.port;
    if (textWidth(ipPort) > 120) {
      ipPort = result.ip.substring(0, 8) + "..:" + result.port;
    }
    text(ipPort, col1X, yPos);
    
    // Service with truncation
    fill(255, 165, 0);
    let service = result.service;
    if (textWidth(service) > 70) {
      service = service.substring(0, 6) + "..";
    }
    text(service, col2X, yPos);
    
    // Version with truncation
    fill(0, 255, 0);
    let version = result.version;
    if (textWidth(version) > 60) {
      version = version.substring(0, 8) + "..";
    }
    text(version, col2X + 75, yPos);
    
    // Banner with truncation
    fill(100, 100, 100);
    let banner = result.banner;
    if (textWidth(banner) > 150) {
      banner = banner.substring(0, 15) + "...";
    }
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
  
  // Focus scanner on current target node
  if (attackSequence.attackInProgress && attackSequence.currentTarget) {
    let targetNode = nodes.find(n => n.ip === attackSequence.currentTarget);
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
          ip: attackSequence.currentTarget,
          port: port,
          service: service,
          version: targetNode.os,
          banner: service + " service on " + targetNode.os
        };
        scanResults.unshift(newResult);
        if (scanResults.length > 20) scanResults.pop();
      }
    }
  }
  
  // Cross-panel coordination: Show scan results that match exploit targets
  if (attackSequence.attackInProgress && attackSequence.currentTarget) {
    let targetExploits = exploitStatus.filter(e => e.target === attackSequence.currentTarget);
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
          ip: attackSequence.currentTarget,
          port: vulnService.port,
          service: vulnService.service,
          version: vulnService.version,
          banner: "VULNERABLE: " + exploit.exploit
        };
        scanResults.unshift(newResult);
        if (scanResults.length > 20) scanResults.pop();
      }
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
  
  // Background with dynamic effect
  fill(0, 20, 0);
  rect(0, 0, w, h);
  stroke(0, 100, 0);
  strokeWeight(1);
  noFill();
  rect(0, 0, w, h);
  
  // Animated background pattern for active exploits
  let runningExploits = exploitStatus.filter(e => e.status === "RUNNING").length;
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
  text("EXPLOITS: " + exploitStatus.length + " | ACTIVE: " + runningExploits + " | SUCCESS: " + exploitStatus.filter(e => e.status === "SUCCESS").length, w/2, 45);
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
        progress: (attackSequence.phaseTimer / attackSequence.phaseDuration) * 100,
        startTime: currentTime,
        estimatedDuration: random(2000, 8000)
      };
      exploitStatus.unshift(newExploit);
      if (exploitStatus.length > 10) exploitStatus.pop();
    }
  }
  
  // Focus exploits on current target node
  if (attackSequence.attackInProgress && attackSequence.currentTarget) {
    let targetNode = nodes.find(n => n.ip === attackSequence.currentTarget);
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
        target: attackSequence.currentTarget,
        status: "RUNNING",
        progress: 0,
        startTime: currentTime,
        estimatedDuration: random(3000, 10000)
      };
      exploitStatus.unshift(newExploit);
      if (exploitStatus.length > 10) exploitStatus.pop();
    }
  }
  
  // Cross-panel coordination: Update node status based on exploit results
  if (attackSequence.attackInProgress && attackSequence.currentTarget) {
    let targetNode = nodes.find(n => n.ip === attackSequence.currentTarget);
    if (targetNode) {
      let successfulExploits = exploitStatus.filter(e => e.target === attackSequence.currentTarget && e.status === "SUCCESS").length;
      if (successfulExploits > 0 && targetNode.status !== "COMPROMISED") {
        targetNode.status = "COMPROMISED";
      } else if (attackSequence.currentPhase >= PHASES.VULNERABILITY_SCAN && targetNode.status === "ACTIVE") {
        targetNode.status = "VULNERABLE";
      }
    }
  }
  
  // Update exploit progress dynamically
  for (let exploit of exploitStatus) {
    if (exploit.status === "RUNNING" && exploit.startTime) {
      let elapsed = currentTime - exploit.startTime;
      exploit.progress = min((elapsed / exploit.estimatedDuration) * 100, 100);
      
      // Randomly complete exploits
      if (exploit.progress >= 100 && random() < 0.1) {
        exploit.status = random() < 0.7 ? "SUCCESS" : "FAILED";
        exploit.progress = 100;
      }
    }
  }
  
  for (let i = 0; i < min(8, exploitStatus.length); i++) {
    let exploit = exploitStatus[i];
    let yPos = startY + i * lineHeight;
    
    // Adjusted column widths to fit panel
    let col1X = 15;    // Exploit name column
    let col2X = 160;   // Target column (reduced)
    let col3X = 240;   // Status column (reduced)
    let col4X = 320;   // Progress bar column
    
    // Exploit name with truncation
    fill(0, 255, 0);
    textAlign(LEFT);
    let exploitName = exploit.exploit;
    if (textWidth(exploitName) > 140) {
      exploitName = exploitName.substring(0, 12) + "..";
    }
    text(exploitName, col1X, yPos);
    
    // Target with truncation
    fill(255, 165, 0);
    let target = exploit.target;
    if (textWidth(target) > 70) {
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
      rect(col4X, yPos - 8, 50, 8);
      
      // Animated progress bar
      let progressColor = color(0, 255, 0);
      if (exploit.progress > 80) {
        progressColor = color(255, 255, 0); // Yellow for near completion
      }
      fill(progressColor);
      rect(col4X, yPos - 8, 50 * exploit.progress / 100, 8);
      
      // Progress percentage
      fill(255, 255, 255);
      textSize(getResponsiveTextSize(8));
      text(floor(exploit.progress) + "%", col4X + 55, yPos);
      
      // Pulsing effect for running exploits
      let pulseSize = 2 + sin(frameCount * 0.2) * 1;
      fill(255, 255, 0, 100);
      ellipse(col4X + 25, yPos - 4, pulseSize, pulseSize);
    } else if (exploit.status === "SUCCESS") {
      // Success indicator
      fill(0, 255, 0);
      textSize(getResponsiveTextSize(8));
      text("✓", col4X + 20, yPos);
    } else if (exploit.status === "FAILED") {
      // Failed indicator
      fill(255, 0, 0);
      textSize(getResponsiveTextSize(8));
      text("✗", col4X + 20, yPos);
    }
  }
  
  // Summary with better layout and dynamic effects
  let runningCount = exploitStatus.filter(e => e.status === "RUNNING").length;
  let successCount = exploitStatus.filter(e => e.status === "SUCCESS").length;
  let failedCount = exploitStatus.filter(e => e.status === "FAILED").length;
  
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
  let totalExploits = exploitStatus.length;
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
  text("TARGET: " + (attackSequence.currentTarget || "NONE"), width/2, height/2 - 20);
  
  // Phase indicator
  let phaseNames = ["TARGET_SELECTION", "TERMINAL_COMMAND", "NETWORK_HIGHLIGHT", "VULNERABILITY_SCAN", "EXPLOIT_EXECUTION"];
  fill(0, 255, 0);
  textSize(getResponsiveTextSize(16));
  text("PHASE: " + phaseNames[attackSequence.currentPhase], width/2, height/2 + 10);
  
  // Progress bar
  let phaseProgress = (attackSequence.phaseTimer / attackSequence.phaseDuration) * 100;
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
