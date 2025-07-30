
let nodes = [];
let terminalLog = [];
let hops = [];
let scanResults = [];
let exploitStatus = [];
let networkTraffic = [];
let currentTime = 0;

function setup() {
  createCanvas(windowWidth, windowHeight);
  textFont("Courier");
  initNodes();
  initHops();
  initScanResults();
  initExploitStatus();
  initNetworkTraffic();
}

function draw() {
  background(0);
  currentTime = millis();
  
  // Calculate grid layout - account for status bar height
  let margin = 10;
  let statusBarHeight = 30;
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
  rect(0, height - 30, width, 30);
  fill(0, 255, 0);
  textSize(12);
  textAlign(LEFT);
  text("KALI LINUX v2024.1 | TARGET: 192.168.1.0/24 | USER: root | SESSION: " + floor(currentTime/1000), 10, height - 10);
  textAlign(RIGHT);
  text("CPU: " + floor(random(20, 80)) + "% | MEM: " + floor(random(40, 90)) + "% | NET: " + floor(random(1, 100)) + " Mbps", width - 10, height - 10);
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
  
  // Title
  fill(0, 255, 0);
  textSize(14);
  textAlign(CENTER);
  text("NETWORK TOPOLOGY", w/2, 20);
  textAlign(LEFT);
  
  // Draw nodes
  for (let i = 0; i < nodes.length; i++) {
    let n = nodes[i];
    // Convert relative coordinates to panel coordinates
    let nodeX = n.x * w;
    let nodeY = n.y * h;
    
    let nodeColor = n.status === "ACTIVE" ? color(0, 255, 0) : 
                n.status === "VULNERABLE" ? color(255, 165, 0) : 
                color(255, 0, 0);
    
    fill(nodeColor);
    noStroke();
    ellipse(nodeX, nodeY, 6, 6);
    
    // Draw connections
    stroke(0, 100, 0);
    strokeWeight(1);
    for (let j = 0; j < 3; j++) {
      let target = nodes[(i + j + 1) % nodes.length];
      let targetX = target.x * w;
      let targetY = target.y * h;
      line(nodeX, nodeY, targetX, targetY);
    }
    
    // Node info
    fill(0, 255, 0);
    textSize(8);
    text(n.ip, nodeX + 8, nodeY - 2);
    text(n.os, nodeX + 8, nodeY + 8);
  }
  
  // Legend
  fill(0, 255, 0);
  textSize(10);
  text("ACTIVE: " + nodes.filter(n => n.status === "ACTIVE").length, 10, h - 60);
  text("VULNERABLE: " + nodes.filter(n => n.status === "VULNERABLE").length, 10, h - 45);
  text("COMPROMISED: " + nodes.filter(n => n.status === "COMPROMISED").length, 10, h - 30);
  
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
  
  // Title
  fill(0, 255, 0);
  textSize(14);
  textAlign(CENTER);
  text("TERMINAL SESSION", w/2, 20);
  textAlign(LEFT);
  
  // Terminal content
  fill(0, 255, 0);
  textSize(10);
  let startY = 35;
  let lineHeight = 12;
  
  // Add realistic terminal output
  if (frameCount % 30 === 0) {
    terminalLog.push(generateTerminalCommand());
    if (terminalLog.length > 15) terminalLog.shift();
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
  
  // Title
  fill(0, 255, 0);
  textSize(14);
  textAlign(CENTER);
  text("VULNERABILITY SCANNER", w/2, 20);
  textAlign(LEFT);
  
  // Scan results
  fill(0, 255, 0);
  textSize(9);
  let startY = 35;
  let lineHeight = 10;
  
  for (let i = 0; i < min(12, scanResults.length); i++) {
    let result = scanResults[i];
    let yPos = startY + i * lineHeight;
    
    // IP and port
    fill(0, 255, 0);
    text(result.ip + ":" + result.port, 10, yPos);
    
    // Service and version
    fill(255, 165, 0);
    text(result.service + " " + result.version, 120, yPos);
    
    // Banner
    fill(100, 100, 100);
    text(result.banner.substring(0, 25), 200, yPos);
  }
  
  // Progress bar
  fill(0, 50, 0);
  rect(10, h - 40, w - 20, 15);
  fill(0, 255, 0);
  rect(10, h - 40, (w - 20) * (frameCount % 100) / 100, 15);
  
  // Status
  fill(0, 255, 0);
  textSize(10);
  text("SCANNING: " + floor((frameCount % 100)) + "% | FOUND: " + scanResults.length + " SERVICES", 10, h - 20);
  
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
  
  // Title
  fill(0, 255, 0);
  textSize(14);
  textAlign(CENTER);
  text("EXPLOIT FRAMEWORK", w/2, 20);
  textAlign(LEFT);
  
  // Exploit status
  fill(0, 255, 0);
  textSize(9);
  let startY = 35;
  let lineHeight = 12;
  
  for (let i = 0; i < min(8, exploitStatus.length); i++) {
    let exploit = exploitStatus[i];
    let yPos = startY + i * lineHeight;
    
    // Exploit name
    fill(0, 255, 0);
    text(exploit.exploit, 10, yPos);
    
    // Target
    fill(255, 165, 0);
    text(exploit.target, 150, yPos);
    
    // Status
    let statusColor = exploit.status === "SUCCESS" ? color(0, 255, 0) :
                     exploit.status === "RUNNING" ? color(255, 165, 0) :
                     exploit.status === "FAILED" ? color(255, 0, 0) : color(100, 100, 100);
    fill(statusColor);
    text(exploit.status, 220, yPos);
    
    // Progress bar
    if (exploit.status === "RUNNING") {
      fill(0, 50, 0);
      rect(280, yPos - 8, 60, 6);
      fill(0, 255, 0);
      rect(280, yPos - 8, 60 * exploit.progress / 100, 6);
    }
  }
  
  // Summary
  fill(0, 255, 0);
  textSize(10);
  text("ACTIVE: " + exploitStatus.filter(e => e.status === "RUNNING").length, 10, h - 30);
  text("SUCCESS: " + exploitStatus.filter(e => e.status === "SUCCESS").length, 10, h - 15);
  
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
  return "root@kali:~# " + random(commands);
}
