// OnionFlow Capture - ofc.go
// OnionOO API integration for real Tor relay detection

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	tsharkPath string
	outputDir  string
	torRelays  []string // Stores Tor relay IP addresses
)

// OnionOOResponse represents the structure of OnionOO API response
type OnionOOResponse struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

// FilteredPacket represents packet data without hex dumps
type FilteredPacket struct {
	FrameNumber int
	FrameLength int
	TCPSeq      string
	Direction   string
	StreamID    int
	PayloadSize int
	IsTorCell   bool
	ContentType string
	Timestamp   int64
	RemoteIP    string
}

// StreamInfo represents analyzed stream data
type StreamInfo struct {
	StreamID    int
	PacketCount int
	TotalBytes  int
	AverageSize int
	Behavior    string
	StartTime   int64
	EndTime     int64
	Packets     []FilteredPacket
}

func init() {
	rand.Seed(time.Now().UnixNano())
	if runtime.GOOS == "windows" {
		// Try both common Wireshark paths
		candidates := []string{
			`C:\Program Files\Wireshark\App\Wireshark\tshark.exe`,
			`C:\Program Files\Wireshark\tshark.exe`,
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				tsharkPath = p
				break
			}
		}
		if tsharkPath == "" {
			tsharkPath = "tshark"
		}
		// Write to current directory instead of Desktop
		outputDir, _ = os.Getwd()
	} else {
		tsharkPath = "tshark"
		// Write to current directory instead of Desktop
		outputDir, _ = os.Getwd()
	}
}

func main() {
	// Admin check (Windows only)
	if runtime.GOOS == "windows" {
		if !isAdmin() {
			fmt.Println("ERROR: Please run as Administrator.")
			pause()
			return
		}
	}

	// TShark check
	if !isTSharkAvailable() {
		fmt.Printf("ERROR: Wireshark not found at \"%s\"\n", tsharkPath)
		fmt.Println("Please install Wireshark or update the TSHARK path.")
		pause()
		return
	}

	// Get local IP
	localIP, err := getLocalIP()
	if err != nil {
		fmt.Println("ERROR: Could not detect local IP address.")
		pause()
		return
	}

	fmt.Println()
	fmt.Println("[+] OnionFlow Capture")
	fmt.Printf("[+] Local IP: %s\n", localIP)
	fmt.Printf("[+] Output directory: %s\n", outputDir)
	fmt.Println()

	// Load Tor relay addresses from OnionOO API
	fmt.Println("[!] Fetching current Tor relay addresses from OnionOO API...")
	if err := loadTorRelays(); err != nil {
		fmt.Printf("[ERROR] Failed to load Tor relays: %v\n", err)
		fmt.Println("[!] Continuing with standard port-based filtering...")
	} else {
		fmt.Printf("[+] Loaded %d Tor relay addresses\n", len(torRelays))
	}

	for {
		packetCount := getPacketCount()
		if packetCount <= 0 {
			break
		}

		// Unix epoch timestamp for all files
		epochTime := time.Now().Unix()
		timestamp := strconv.FormatInt(epochTime, 10)

		// Filenames with epoch timestamp
		outputFile := filepath.Join(outputDir, fmt.Sprintf("tor_capture_%s.txt", timestamp))
		analysisFile := filepath.Join(outputDir, fmt.Sprintf("tor_analysis_%s.txt", timestamp))
		streamsFile := filepath.Join(outputDir, fmt.Sprintf("tor_streams_%s.txt", timestamp))
		payloadsFile := filepath.Join(outputDir, fmt.Sprintf("tor_payloads_%s.txt", timestamp))
		relaysFile := filepath.Join(outputDir, fmt.Sprintf("tor_relays_%s.txt", timestamp))

		fmt.Println()
		fmt.Printf("[!] Starting capture: %s\n", time.Unix(epochTime, 0).Format("2006-01-02 15:04:05"))
		fmt.Printf("[!] Capturing %d packets...\n", packetCount)

		// Get network interface - use WLAN directly
		interfaceName := getNetworkInterface()
		fmt.Printf("[+] Using interface: %s\n", interfaceName)
		fmt.Printf("[!] Local IP: %s\n", localIP)
		fmt.Println()

		// Write header with epoch time
		writeFile(analysisFile, `TOR TRAFFIC ANALYSIS
=========================================
Session ID: `+timestamp+`
Unix Timestamp: `+timestamp+`
Requested packets: `+strconv.Itoa(packetCount)+`
Tor relays detected: `+strconv.Itoa(len(torRelays))+`
Interface: `+interfaceName+`
Local IP: `+localIP+`

`)

		// Formatted table for capture
		writeFile(outputFile, `TOR TRAFFIC CAPTURE - FILTERED
=========================================
UnixTime     | FrameNr | Length | Direction | StreamID | ContentType | RemoteIP
-------------|---------|--------|-----------|----------|-------------|-----------
`)

		// Formatted table for streams
		writeFile(streamsFile, `TOR STREAMS ANALYSIS
=========================================
StreamID | PacketCount | TotalBytes | AverageSize | Behavior  | StartTime   | EndTime
---------|-------------|------------|-------------|-----------|-------------|------------
`)

		writeFile(payloadsFile, `USER PAYLOADS ANALYSIS
=========================================
Pattern|RiskLevel|UploadPackets|DownloadPackets|TotalData|Timestamp
`)

		// Write relay information to file
		writeRelayInfo(relaysFile)

		// Capture filtered traffic without hex dumps
		fmt.Println("[!] Starting packet capture...")
		filteredPackets := captureFilteredTraffic(interfaceName, packetCount, localIP, epochTime)

		if len(filteredPackets) == 0 {
			// No traffic captured
			fmt.Println()
			fmt.Println("[ERROR] NO TRAFFIC CAPTURED")
			fmt.Println("==========================")
			fmt.Println("No Tor relay traffic detected")
			fmt.Println()
			fmt.Println("[!] Check Tor connection and activity")
			fmt.Println()

			appendFile(analysisFile, `ERROR: NO TRAFFIC CAPTURED
=========================
Session: `+timestamp+`
Requested: `+strconv.Itoa(packetCount)+` packets
Captured: 0 packets
Tor relays available: `+strconv.Itoa(len(torRelays))+`

No Tor relay traffic detected
`)
		} else {
			// Write filtered packets to output file
			writeFilteredCapture(outputFile, filteredPackets)

			// Analyze streams and write stream analysis
			streamAnalysis := analyzeStreams(filteredPackets)
			writeStreamAnalysis(streamsFile, streamAnalysis, epochTime)

			// Calculate statistics
			uploadPackets := 0
			downloadPackets := 0
			totalUploadData := 0
			totalDownloadData := 0
			torCells := 0
			userPackets := 0
			uniqueRelays := make(map[string]bool)

			for _, pkt := range filteredPackets {
				if pkt.Direction == "UPLOAD" {
					uploadPackets++
					totalUploadData += pkt.FrameLength
				} else if pkt.Direction == "DOWNLOAD" {
					downloadPackets++
					totalDownloadData += pkt.FrameLength
				}
				
				// Count Tor Cells vs User Packets
				if pkt.IsTorCell {
					torCells++
				} else {
					userPackets++
				}
				
				if pkt.RemoteIP != "" {
					uniqueRelays[pkt.RemoteIP] = true
				}
			}

			totalPackets := uploadPackets + downloadPackets
			totalStreams := len(streamAnalysis)
			if totalStreams < 1 && totalPackets > 0 {
				totalStreams = 1
			}

			uploadRatio := 0
			if totalPackets > 0 {
				uploadRatio = (uploadPackets * 100) / totalPackets
			}

			behaviorPattern := "UNKNOWN"
			identificationRisk := 0
			if totalPackets > 0 {
				switch {
				case uploadRatio > 60:
					behaviorPattern = "UPLOAD"
					identificationRisk = 50
				case uploadRatio > 40:
					behaviorPattern = "BALANCED"
					identificationRisk = 35
				case uploadRatio > 20:
					behaviorPattern = "BROWSING"
					identificationRisk = 25
				default:
					behaviorPattern = "DOWNLOAD"
					identificationRisk = 15
				}
			}

			// Write analysis files
			writeAnalysisFile(analysisFile, packetCount, totalPackets, totalStreams, uploadPackets,
				downloadPackets, torCells, userPackets, behaviorPattern, identificationRisk, 
				epochTime, len(uniqueRelays))

			writePayloadsFile(payloadsFile, behaviorPattern, identificationRisk, uploadPackets,
				downloadPackets, totalUploadData+totalDownloadData, epochTime, len(uniqueRelays))

			// Success message
			fmt.Println()
			fmt.Println("[+] ANALYSIS COMPLETE")
			fmt.Println("====================================================")
			fmt.Printf("Requested packets: %d\n", packetCount)
			fmt.Printf("Actual packets: %d\n", totalPackets)
			fmt.Printf("TCP streams: %d\n", totalStreams)
			fmt.Printf("Upload packets: %d\n", uploadPackets)
			fmt.Printf("Download packets: %d\n", downloadPackets)
			fmt.Printf("Tor cells: %d\n", torCells)
			fmt.Printf("User packets: %d\n", userPackets)
			fmt.Printf("Total upload: %d bytes\n", totalUploadData)
			fmt.Printf("Total download: %d bytes\n", totalDownloadData)
			fmt.Printf("Unique Tor relays: %d\n", len(uniqueRelays))
			fmt.Printf("Behavioral Pattern: %s\n", behaviorPattern)
			fmt.Printf("Identification Risk: %d%%\n", identificationRisk)
			fmt.Println()
			fmt.Printf("Unix timestamp: %s\n", timestamp)
			fmt.Println()
			fmt.Println("Files created:")
			fmt.Println("-", analysisFile)
			fmt.Println("-", streamsFile)
			fmt.Println("-", payloadsFile)
			fmt.Println("-", outputFile)
			fmt.Println("-", relaysFile)
			fmt.Println()
		}

		// Again?
		fmt.Print("Press Enter to capture again or Q to quit... ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if strings.ToUpper(input) == "Q" {
			break
		}
	}

	fmt.Println()
	fmt.Println("OnionFlow Capture terminated.")
	fmt.Println("Goodbye!")
}

// loadTorRelays fetches current Tor relay addresses from OnionOO API
func loadTorRelays() error {
	client := &http.Client{Timeout: 30 * time.Second}
	
	// OnionOO API endpoint for current relays
	url := "https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses"
	
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch OnionOO API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OnionOO API returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read API response: %v", err)
	}

	var apiResponse OnionOOResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Extract IP addresses from or_addresses
	torRelays = []string{}
	for _, relay := range apiResponse.Relays {
		for _, addr := range relay.OrAddresses {
			// Parse addresses like "185.220.101.397:443" or "[2001:db8::1]:443"
			ip := extractIPFromAddress(addr)
			if ip != "" {
				torRelays = append(torRelays, ip)
			}
		}
	}

	if len(torRelays) == 0 {
		return fmt.Errorf("no Tor relay addresses found in API response")
	}

	// Remove duplicates
	torRelays = removeDuplicates(torRelays)
	
	fmt.Printf("[+] Found %d unique Tor relay IP addresses\n", len(torRelays))
	
	return nil
}

// extractIPFromAddress extracts IP from address string like "ip:port" or "[ip]:port"
func extractIPFromAddress(addr string) string {
	// Handle IPv6 format: [2001:db8::1]:443
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end > 0 {
			return addr[1:end]
		}
	}
	
	// Handle IPv4 format: 185.220.101.397:443
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		return parts[0]
	}
	
	return ""
}

// removeDuplicates removes duplicate IP addresses from slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result
}

// writeRelayInfo writes Tor relay information to file
func writeRelayInfo(relaysFile string) {
	writeFile(relaysFile, `TOR RELAY INFORMATION
=========================================
Source: OnionOO Tor Project API
Timestamp: `+strconv.FormatInt(time.Now().Unix(), 10)+`
Total relays: `+strconv.Itoa(len(torRelays))+`

Relay IP Addresses:
------------------
`)

	for _, relay := range torRelays {
		appendFile(relaysFile, relay+"\n")
	}
}

// isTorRelay checks if an IP address belongs to a known Tor relay
func isTorRelay(ip string) bool {
	for _, relay := range torRelays {
		if ip == relay {
			return true
		}
	}
	return false
}

// getNetworkInterface returns the WLAN interface directly
func getNetworkInterface() string {
	// List all available interfaces
	cmd := exec.Command(tsharkPath, "-D")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[ERROR] Cannot list interfaces: %v\n", err)
		return "any"
	}

	interfaces := strings.Split(strings.TrimSpace(string(output)), "\n")
	
	// Search for WLAN interface
	for _, ifaceLine := range interfaces {
		displayName := extractDisplayName(ifaceLine)
		if strings.Contains(strings.ToLower(displayName), "wlan") {
			interfaceName := extractInterfaceName(ifaceLine)
			return interfaceName
		}
	}

	// Fallback to any
	return "any"
}

// extractInterfaceName extracts the interface device name from tshark -D output
func extractInterfaceName(line string) string {
	// tshark -D output format: "1. \Device\NPF_{GUID} (Display Name)"
	parts := strings.SplitN(line, ". ", 2)
	if len(parts) > 1 {
		nameParts := strings.SplitN(parts[1], " ", 2)
		return strings.TrimSpace(nameParts[0])
	}
	return strings.TrimSpace(line)
}

// extractDisplayName extracts the display name in parentheses from tshark -D output
func extractDisplayName(line string) string {
	// Find content in parentheses: "1. \Device\NPF_{GUID} (Display Name)"
	start := strings.Index(line, "(")
	end := strings.Index(line, ")")
	if start > 0 && end > start {
		return strings.TrimSpace(line[start+1 : end])
	}
	return ""
}

// captureFilteredTraffic captures network packets without hex dumps
func captureFilteredTraffic(interfaceName string, packetCount int, localIP string, startTime int64) []FilteredPacket {
	var filteredPackets []FilteredPacket

	// Capture ALL TCP traffic and filter later in code
	filter := "tcp"
	fmt.Printf("[+] Using filter: %s\n", filter)
	fmt.Println("[!] Capturing all TCP traffic (post-filtering for Tor relays)...")

	cmd := exec.Command(tsharkPath, "-i", interfaceName, "-c", strconv.Itoa(packetCount),
		"-f", filter,
		"-T", "fields",
		"-e", "frame.number",
		"-e", "frame.len",
		"-e", "tcp.seq",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.stream",
		"-e", "tcp.len")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[ERROR] Cannot create stdout pipe: %v\n", err)
		return filteredPackets
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Printf("[ERROR] Cannot create stderr pipe: %v\n", err)
		return filteredPackets
	}

	// Start command
	if err := cmd.Start(); err != nil {
		fmt.Printf("[ERROR] Cannot start capture: %v\n", err)
		return filteredPackets
	}

	// Read stderr for error messages
	errorOutput := ""
	go func() {
		errorScanner := bufio.NewScanner(stderr)
		for errorScanner.Scan() {
			line := errorScanner.Text()
			errorOutput += line + "\n"
		}
	}()

	// Process stdout
	scanner := bufio.NewScanner(stdout)
	packetsProcessed := 0
	torPackets := 0
	allPackets := 0

	for scanner.Scan() {
		allPackets++
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 7 {
			continue
		}

		// Parse packet fields
		frameNum, _ := strconv.Atoi(fields[0])
		frameLen, _ := strconv.Atoi(fields[1])
		tcpSeq := fields[2]
		ipSrc := fields[3]
		ipDst := fields[4]
		streamID, _ := strconv.Atoi(fields[5])
		tcpLen, _ := strconv.Atoi(fields[6])

		// Skip packets without payload
		if tcpLen <= 0 {
			continue
		}

		// Only process traffic to/from local machine
		if ipSrc != localIP && ipDst != localIP {
			continue
		}

		// Determine direction and remote IP
		direction := "DOWNLOAD"
		remoteIP := ipSrc
		if ipSrc == localIP {
			direction = "UPLOAD"
			remoteIP = ipDst
		}

		// Check if this is a Tor relay - POST-FILTERING here!
		if !isTorRelay(remoteIP) {
			continue
		}

		// CORRECTED: Improved classification for Tor traffic
		isTorCell := false
		contentType := "UNKNOWN"
		
		// Extended Tor cell detection including network overhead
		// Tor cells are 512 bytes, but with headers they become ~566-590 bytes
		if frameLen >= 510 && frameLen <= 600 {
			isTorCell = true
			
			// Further classification within Tor traffic range
			if tcpLen == 0 {
				contentType = "CONTROL"
			} else if tcpLen <= 100 {
				contentType = "TOR_CONTROL"
			} else if tcpLen == 512 {
				contentType = "TOR_CELL"        // Exact Tor cell size
			} else if tcpLen > 512 && tcpLen <= 1000 {
				contentType = "TOR_DATA_CELL"   // Tor cell with data
			} else {
				contentType = "TOR_TRAFFIC"     // General Tor traffic
			}
		} else if tcpLen > 2000 {
			contentType = "LARGE_DATA"
		} else if tcpLen > 1000 {
			contentType = "MEDIUM_DATA"
		} else if tcpLen > 500 {
			contentType = "SMALL_DATA"
		} else if tcpLen > 100 {
			contentType = "CONTROL_DATA"
		} else {
			contentType = "CONTROL"
			isTorCell = true // Small control packets are likely Tor cells
		}

		// Create filtered packet without hex dumps
		packet := FilteredPacket{
			FrameNumber: frameNum,
			FrameLength: frameLen,
			TCPSeq:      tcpSeq,
			Direction:   direction,
			StreamID:    streamID,
			PayloadSize: tcpLen,
			IsTorCell:   isTorCell,
			ContentType: contentType,
			Timestamp:   startTime + int64(frameNum),
			RemoteIP:    remoteIP,
		}

		filteredPackets = append(filteredPackets, packet)
		packetsProcessed++
		torPackets++
	}

	// Wait for command to finish
	cmd.Wait()

	fmt.Printf("[+] Capture completed: %d total packets, %d Tor packets processed\n", allPackets, torPackets)

	if packetsProcessed == 0 {
		fmt.Println("[!] No Tor packets captured.")
		fmt.Println("[!] Make sure Tor is running")
		if errorOutput != "" {
			fmt.Printf("[!] TShark output: %s\n", errorOutput)
		}
	}

	return filteredPackets
}

// writeFilteredCapture writes filtered packets to output file with Unix timestamps
func writeFilteredCapture(outputFile string, packets []FilteredPacket) {
	packetsWritten := 0
	for _, pkt := range packets {
		// Formatted lines with fixed column width for Capture
		line := fmt.Sprintf("%-12d | %-7d | %-6d | %-9s | %-8d | %-11s | %s\n",
			pkt.Timestamp,
			pkt.FrameNumber,
			pkt.FrameLength,
			pkt.Direction,
			pkt.StreamID,
			pkt.ContentType,
			pkt.RemoteIP)

		appendFile(outputFile, line)
		packetsWritten++
	}
	fmt.Printf("[+] Written %d packets to capture file\n", packetsWritten)
}

// analyzeStreams groups packets into streams and calculates stream statistics
func analyzeStreams(packets []FilteredPacket) []StreamInfo {
	streams := make(map[int]*StreamInfo)

	// Group packets by stream ID
	for _, pkt := range packets {
		if _, exists := streams[pkt.StreamID]; !exists {
			// Initialize new stream
			streams[pkt.StreamID] = &StreamInfo{
				StreamID:   pkt.StreamID,
				StartTime:  pkt.Timestamp,
				EndTime:    pkt.Timestamp,
				Packets:    []FilteredPacket{},
			}
		}

		stream := streams[pkt.StreamID]
		stream.PacketCount++
		stream.TotalBytes += pkt.FrameLength
		stream.Packets = append(stream.Packets, pkt)

		// Update time range
		if pkt.Timestamp < stream.StartTime {
			stream.StartTime = pkt.Timestamp
		}
		if pkt.Timestamp > stream.EndTime {
			stream.EndTime = pkt.Timestamp
		}
	}

	// Calculate stream statistics and behavior
	var result []StreamInfo
	for _, stream := range streams {
		if stream.PacketCount > 0 {
			// Calculate average packet size
			stream.AverageSize = stream.TotalBytes / stream.PacketCount

			// Analyze stream behavior based on direction ratio
			uploadCount := 0
			for _, pkt := range stream.Packets {
				if pkt.Direction == "UPLOAD" {
					uploadCount++
				}
			}

			uploadRatio := (uploadCount * 100) / stream.PacketCount

			// Classify stream behavior
			switch {
			case uploadRatio > 70:
				stream.Behavior = "UPLOAD"
			case uploadRatio > 30:
				stream.Behavior = "BALANCED"
			default:
				stream.Behavior = "DOWNLOAD"
			}

			result = append(result, *stream)
		}
	}

	return result
}

// writeStreamAnalysis writes stream analysis to file with timing information
func writeStreamAnalysis(streamsFile string, streams []StreamInfo, sessionTime int64) {
	streamsWritten := 0
	for _, stream := range streams {
		// Formatted lines with fixed column width
		line := fmt.Sprintf("%-8d | %-11d | %-10d | %-11d | %-8s | %-11d | %-9d\n",
			stream.StreamID,
			stream.PacketCount,
			stream.TotalBytes,
			stream.AverageSize,
			stream.Behavior,
			stream.StartTime,
			stream.EndTime)

		appendFile(streamsFile, line)
		streamsWritten++
	}
	fmt.Printf("[+] Written %d streams to analysis file\n", streamsWritten)
}

// writeAnalysisFile writes the main analysis file
func writeAnalysisFile(analysisFile string, requested, actual, streams, upload, download, torCells, userPackets int, pattern string, risk int, timestamp int64, uniqueRelays int) {
	appendFile(analysisFile, fmt.Sprintf(`
CAPTURE STATISTICS:
------------------
Requested packets: %d
Actual packets: %d
TCP streams: %d
Consistent streams: %d
Upload packets: %d
Download packets: %d
Tor cells: %d
User packets: %d
Unique Tor relays: %d
Behavioral Pattern: %s
Identification Risk: %d%%
Session Timestamp: %d

FORENSIC ASSESSMENT:
-------------------
%s
`,
		requested, actual, streams, streams, upload, download,
		torCells, userPackets, uniqueRelays,
		pattern, risk, timestamp,
		riskMessage(risk)))
}

// writePayloadsFile writes payload analysis file
func writePayloadsFile(payloadsFile, pattern string, risk, upload, download, totalData int, timestamp int64, uniqueRelays int) {
	appendFile(payloadsFile, fmt.Sprintf(`
BEHAVIORAL PATTERN INFERENCE:
============================
Pattern: %s

IDENTIFICATION RISK ASSESSMENT:
=============================
Risk Level: %d/100
%s

SESSION DATA:
============
Upload Packets: %d
Download Packets: %d
Total Data: %d bytes
Unique Tor Relays: %d
Timestamp: %d
`,
		pattern, risk, riskMessageShort(risk), upload, download, totalData, uniqueRelays, timestamp))
}

// --- Helper functions ---

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func isTSharkAvailable() bool {
	if _, err := os.Stat(tsharkPath); err == nil {
		return true
	}
	_, err := exec.LookPath("tshark")
	return err == nil
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func getPacketCount() int {
	fmt.Print("Enter number of packets to capture (default: 1000, Q to quit): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	if input == "" {
		return 1000
	}
	if strings.ToUpper(input) == "Q" {
		return 0
	}
	count, err := strconv.Atoi(input)
	if err != nil || count <= 0 {
		return 1000
	}
	return count
}

func writeFile(path, content string) {
	os.WriteFile(path, []byte(content), 0644)
}

func appendFile(path, content string) {
	file, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	file.WriteString(content)
	file.Close()
}

func riskMessage(risk int) string {
	switch {
	case risk >= 50:
		return "[MEDIUM] IDENTIFIABLE PATTERNS DETECTED"
	case risk >= 30:
		return "[LOW-MEDIUM] SOME PATTERNS DETECTED"
	default:
		return "[LOW] MINIMAL IDENTIFICATION RISK"
	}
}

func riskMessageShort(risk int) string {
	switch {
	case risk >= 50:
		return "[!] MEDIUM RISK: Some identifiable patterns detected"
	case risk >= 30:
		return "[!] LOW-MEDIUM RISK: Minimal identification patterns"
	default:
		return "[!] LOW RISK: Good anonymity preservation"
	}
}

func pause() {
	if runtime.GOOS == "windows" {
		fmt.Print("Press any key to continue . . . ")
		var input string
		fmt.Scanln(&input)
	}
}
