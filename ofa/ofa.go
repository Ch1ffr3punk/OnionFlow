// OnionFlow Analyzer - ofa.go

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Session represents analysis session data
type Session struct {
	Timestamp   string
	EpochTime   int64
	Packets     int
	Streams     int
	Consistent  int
	TorCells    int
	UserPackets int
	Pattern     string
	Risk        int
	Assessment  string
	StreamsFile string
	StreamData  []StreamInfo
}

// StreamInfo represents detailed stream information
type StreamInfo struct {
	StreamID    int
	StartFrame  int
	EndFrame    int
	PacketCount int
	TotalBytes  int
	AverageSize int
	Behavior    string
	StartTime   int64
	EndTime     int64
	Packets     []PacketInfo
}

// PacketInfo represents individual packet data
type PacketInfo struct {
	FrameNumber int
	FrameLength int
	Direction   string
	Timestamp   int64
}

func main() {
	fmt.Println("=== OnionFlow Analyzer ===")
	fmt.Println("Generating comprehensive analysis report...")
	fmt.Println()

	currentDir, _ := os.Getwd()
	reportsDir := filepath.Join(currentDir, "reports")
	
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		fmt.Printf("Error creating reports directory: %v\n", err)
		fmt.Println("Using current directory instead...")
		reportsDir = currentDir
	}

	analysisFiles := findAnalysisFiles(currentDir)
	streamsFiles := findStreamsFiles(currentDir)
	
	fmt.Printf("Analysis files found: %d\n", len(analysisFiles))
	fmt.Printf("Streams files found: %d\n", len(streamsFiles))

	if len(analysisFiles) == 0 {
		fmt.Println("ERROR: No analysis files found!")
		return
	}

	sessions := parseSessionsWithStreams(analysisFiles, streamsFiles)
	
	if len(sessions) == 0 {
		fmt.Println("ERROR: No valid sessions found!")
		return
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	
	generateSessionTable(sessions, reportsDir, timestamp)
	generateSummaryReport(sessions, reportsDir, timestamp)
	generateBehavioralReport(sessions, reportsDir, timestamp)
	generateDetailedStreamReport(sessions, reportsDir, timestamp)
	generateUserFriendlyReport(sessions, reportsDir, timestamp)
	generateStreamCorrelationReport(sessions, reportsDir, timestamp)
	
	fmt.Printf("\nAll reports generated successfully!\n")
	fmt.Printf("Total sessions analyzed: %d\n", len(sessions))
	fmt.Printf("Reports saved to: %s\n", reportsDir)
	fmt.Printf("Analysis timestamp: %s\n", timestamp)
}

// findAnalysisFiles locates analysis files in current directory
func findAnalysisFiles(currentDir string) []string {
	var files []string
	pattern := "tor_analysis_*.txt"
	
	matches, err := filepath.Glob(filepath.Join(currentDir, pattern))
	if err == nil {
		files = append(files, matches...)
	}
	
	return files
}

// findStreamsFiles locates streams files in current directory
func findStreamsFiles(currentDir string) []string {
	var files []string
	pattern := "tor_streams_*.txt"
	
	matches, err := filepath.Glob(filepath.Join(currentDir, pattern))
	if err == nil {
		files = append(files, matches...)
	}
	
	return files
}

// parseSessionsWithStreams parses sessions with correlated stream data
func parseSessionsWithStreams(analysisFiles, streamsFiles []string) []Session {
	var sessions []Session
	processedTimestamps := make(map[string]bool)
	
	// Create mapping for streams files
	streamsMap := make(map[string]string)
	for _, streamFile := range streamsFiles {
		timestamp := extractTimestampFromFilename(streamFile)
		if timestamp != "" {
			streamsMap[timestamp] = streamFile
		}
	}
	
	for _, analysisFile := range analysisFiles {
		session := parseSession(analysisFile)
		timestamp := extractTimestampFromFilename(analysisFile)
		
		// Add streams data if available
		if streamsFile, exists := streamsMap[timestamp]; exists {
			session.StreamsFile = streamsFile
			session.StreamData = parseStreamsFile(streamsFile)
		}
		
		// Only add if we have packets and it's not a duplicate
		if session.Packets > 0 && !processedTimestamps[timestamp] {
			sessions = append(sessions, session)
			processedTimestamps[timestamp] = true
			fmt.Printf("Session: %s, Packets: %d, Streams: %d, Pattern: %s\n", 
				time.Unix(session.EpochTime, 0).Format("15:04:05"), 
				session.Packets, session.Streams, session.Pattern)
		}
	}
	
	// Sort by time
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].EpochTime < sessions[j].EpochTime
	})
	
	return sessions
}

// extractTimestampFromFilename extracts Unix timestamp from filename
func extractTimestampFromFilename(filename string) string {
	re := regexp.MustCompile(`tor_\w+_(\d+)\.txt`)
	matches := re.FindStringSubmatch(filepath.Base(filename))
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// parseSession extracts session data from analysis file
func parseSession(filename string) Session {
	session := Session{}
	file, err := os.Open(filename)
	if err != nil {
		return session
	}
	defer file.Close()

	// Extract timestamp from filename
	re := regexp.MustCompile(`tor_analysis_(\d+)\.txt`)
	matches := re.FindStringSubmatch(filepath.Base(filename))
	
	if len(matches) == 2 {
		epochTime, _ := strconv.ParseInt(matches[1], 10, 64)
		session.EpochTime = epochTime
		session.Timestamp = matches[1]
	}

	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		
		if strings.Contains(line, "Actual packets:") {
			session.Packets = extractNumber(line)
		} else if strings.Contains(line, "TCP streams:") {
			session.Streams = extractNumber(line)
		} else if strings.Contains(line, "Consistent streams:") {
			session.Consistent = extractNumber(line)
		} else if strings.Contains(line, "Tor cells:") {
			session.TorCells = extractNumber(line)
		} else if strings.Contains(line, "User packets:") {
			session.UserPackets = extractNumber(line)
		} else if strings.Contains(line, "Behavioral Pattern:") {
			if parts := strings.Split(line, ":"); len(parts) >= 2 {
				session.Pattern = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Identification Risk:") {
			session.Risk = extractNumber(line)
		} else if strings.Contains(line, "[HIGH]") {
			session.Assessment = "HIGH"
		} else if strings.Contains(line, "[MEDIUM]") {
			session.Assessment = "MEDIUM"
		} else if strings.Contains(line, "[LOW]") {
			session.Assessment = "LOW"
		}
	}
	
	// Fallback: If we couldn't find the new fields, estimate them
	if session.TorCells == 0 && session.Packets > 0 {
		// Estimate based on typical Tor traffic patterns
		session.TorCells = session.Packets * 2 / 3
	}
	if session.UserPackets == 0 && session.Packets > 0 {
		session.UserPackets = session.Packets - session.TorCells
		if session.UserPackets < 0 {
			session.UserPackets = session.Packets / 3
		}
	}
	
	if session.Assessment == "" {
		session.Assessment = "UNKNOWN"
	}
	if session.Pattern == "" {
		session.Pattern = "MIXED"
	}
	
	return session
}

// parseStreamsFile parses stream data with Unix timestamps
func parseStreamsFile(filename string) []StreamInfo {
	var streams []StreamInfo
	file, err := os.Open(filename)
	if err != nil {
		return streams
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNumber++
		
		// Skip header lines
		if lineNumber <= 3 || strings.Contains(line, "StreamID") || strings.Contains(line, "---------") {
			continue
		}
		
		// Parse stream data line
		// Format: "StreamID | PacketCount | TotalBytes | AverageSize | Behavior  | StartTime   | EndTime"
		fields := strings.Split(line, "|")
		if len(fields) >= 7 {
			// Entferne Leerzeichen von jedem Feld
			for i := range fields {
				fields[i] = strings.TrimSpace(fields[i])
			}
			
			streamID, _ := strconv.Atoi(fields[0])
			packetCount, _ := strconv.Atoi(fields[1])
			totalBytes, _ := strconv.Atoi(fields[2])
			averageSize, _ := strconv.Atoi(fields[3])
			behavior := fields[4]
			startTime, _ := strconv.ParseInt(fields[5], 10, 64)
			endTime, _ := strconv.ParseInt(fields[6], 10, 64)
			
			stream := StreamInfo{
				StreamID:    streamID,
				PacketCount: packetCount,
				TotalBytes:  totalBytes,
				AverageSize: averageSize,
				Behavior:    behavior,
				StartTime:   startTime,
				EndTime:     endTime,
				Packets:     []PacketInfo{},
			}
			
			streams = append(streams, stream)
		}
	}
	
	return streams
}

// extractNumber extracts first number from string
func extractNumber(line string) int {
	re := regexp.MustCompile(`(\d+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 0 {
		num, err := strconv.Atoi(matches[1])
		if err == nil {
			return num
		}
	}
	return 0
}

// generateSessionTable creates session overview table
func generateSessionTable(sessions []Session, reportsDir string, timestamp string) {
	tableFile := filepath.Join(reportsDir, fmt.Sprintf("tor_session_table_%s.txt", timestamp))
	
	file, err := os.Create(tableFile)
	if err != nil {
		fmt.Printf("Error creating session table: %v\n", err)
		return
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	writer.WriteString("TOR TRAFFIC SESSION ANALYSIS\n")
	writer.WriteString("=============================\n\n")
	writer.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Analysis ID: %s\n\n", timestamp))
	
	writer.WriteString("Session | UnixTimestamp    | DateTime            | Packets | Streams | Pattern  | Risk | Assessment\n")
	writer.WriteString("--------+------------------+---------------------+---------+---------+----------+------+------------\n")
	
	for i, session := range sessions {
		dateTime := time.Unix(session.EpochTime, 0).Format("2006-01-02 15:04:05")
		writer.WriteString(fmt.Sprintf("%-7d | %-16d | %-18s | %-7d | %-7d | %-8s | %-4d | %s\n",
			i+1, session.EpochTime, dateTime, session.Packets, session.Streams, 
			session.Pattern, session.Risk, session.Assessment))
	}
	
	writer.WriteString("\nSUMMARY:\n")
	writer.WriteString(fmt.Sprintf("Total sessions: %d\n", len(sessions)))
	
	totalPackets := 0
	for _, s := range sessions {
		totalPackets += s.Packets
	}
	writer.WriteString(fmt.Sprintf("Total packets: %d\n", totalPackets))
	
	writer.Flush()
	fmt.Printf("Session table saved to: %s\n", tableFile)
}

// generateSummaryReport creates detailed session report
func generateSummaryReport(sessions []Session, reportsDir string, timestamp string) {
	reportFile := filepath.Join(reportsDir, fmt.Sprintf("tor_analysis_report_%s.txt", timestamp))
	
	file, _ := os.Create(reportFile)
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	writer.WriteString("DETAILED TOR TRAFFIC ANALYSIS REPORT\n")
	writer.WriteString("====================================\n\n")
	writer.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Analysis ID: %s\n\n", timestamp))
	
	writer.WriteString(fmt.Sprintf("Total Sessions Analyzed: %d\n\n", len(sessions)))
	
	for i, session := range sessions {
		writer.WriteString(fmt.Sprintf("SESSION %d:\n", i+1))
		writer.WriteString(fmt.Sprintf("Unix Time: %d\n", session.EpochTime))
		writer.WriteString(fmt.Sprintf("Date/Time: %s\n", time.Unix(session.EpochTime, 0).Format("2006-01-02 15:04:05")))
		writer.WriteString(fmt.Sprintf("Packets: %d, Streams: %d, Consistent: %d\n", 
			session.Packets, session.Streams, session.Consistent))
		writer.WriteString(fmt.Sprintf("Tor Cells: %d, User Packets: %d\n", 
			session.TorCells, session.UserPackets))
		writer.WriteString(fmt.Sprintf("Pattern: %s, Risk: %d%%, Assessment: %s\n", 
			session.Pattern, session.Risk, session.Assessment))
		
		// Add stream information if available - mit schöner Formatierung
		if len(session.StreamData) > 0 {
			writer.WriteString(fmt.Sprintf("\nStream Analysis (%d streams):\n", len(session.StreamData)))
			writer.WriteString("StreamID | Packets | TotalBytes | AvgSize | Behavior | Duration\n")
			writer.WriteString("---------|---------|------------|---------|----------|---------\n")
			
			for _, stream := range session.StreamData {
				duration := stream.EndTime - stream.StartTime
				writer.WriteString(fmt.Sprintf("%-8d | %-7d | %-10d | %-7d | %-8s | %-8d\n",
					stream.StreamID, stream.PacketCount, stream.TotalBytes, 
					stream.AverageSize, stream.Behavior, duration))
			}
		}
		writer.WriteString("\n" + strings.Repeat("-", 50) + "\n\n")
	}
	
	writer.Flush()
	fmt.Printf("Analysis report saved to: %s\n", reportFile)
}

// generateBehavioralReport creates pattern analysis report
func generateBehavioralReport(sessions []Session, reportsDir string, timestamp string) {
	reportFile := filepath.Join(reportsDir, fmt.Sprintf("tor_behavioral_analysis_%s.txt", timestamp))
	
	file, _ := os.Create(reportFile)
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	writer.WriteString("BEHAVIORAL PATTERN ANALYSIS\n")
	writer.WriteString("===========================\n\n")
	writer.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Analysis ID: %s\n\n", timestamp))
	
	patternCount := make(map[string]int)
	totalRisk := 0
	
	for _, session := range sessions {
		patternCount[session.Pattern]++
		totalRisk += session.Risk
	}
	
	writer.WriteString("PATTERN DISTRIBUTION:\n")
	for pattern, count := range patternCount {
		percentage := float64(count) / float64(len(sessions)) * 100
		writer.WriteString(fmt.Sprintf("  %s: %d sessions (%.1f%%)\n", pattern, count, percentage))
	}
	
	avgRisk := 0
	if len(sessions) > 0 {
		avgRisk = totalRisk / len(sessions)
	}
	
	writer.WriteString(fmt.Sprintf("\nAVERAGE RISK SCORE: %d%%\n", avgRisk))
	
	if avgRisk >= 50 {
		writer.WriteString("OVERALL ASSESSMENT: MEDIUM-HIGH RISK\n")
	} else if avgRisk >= 30 {
		writer.WriteString("OVERALL ASSESSMENT: LOW-MEDIUM RISK\n")
	} else {
		writer.WriteString("OVERALL ASSESSMENT: LOW RISK\n")
	}
	
	writer.Flush()
	fmt.Printf("Behavioral analysis saved to: %s\n", reportFile)
}

// generateDetailedStreamReport creates stream correlation analysis
func generateDetailedStreamReport(sessions []Session, reportsDir string, timestamp string) {
	streamReportFile := filepath.Join(reportsDir, fmt.Sprintf("tor_detailed_stream_analysis_%s.txt", timestamp))
	
	file, _ := os.Create(streamReportFile)
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	writer.WriteString("DETAILED STREAM CORRELATION ANALYSIS\n")
	writer.WriteString("====================================\n\n")
	writer.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Analysis ID: %s\n\n", timestamp))
	
	for i, session := range sessions {
		writer.WriteString(fmt.Sprintf("SESSION %d - Unix Time: %d\n", i+1, session.EpochTime))
		writer.WriteString(fmt.Sprintf("DateTime: %s\n", time.Unix(session.EpochTime, 0).Format("2006-01-02 15:04:05")))
		writer.WriteString(fmt.Sprintf("Pattern: %s, Risk: %d%%, Total Packets: %d\n\n", 
			session.Pattern, session.Risk, session.Packets))
		
		if len(session.StreamData) > 0 {
			writer.WriteString("STREAM CORRELATION ANALYSIS:\n")
			writer.WriteString("============================\n")
			
			for _, stream := range session.StreamData {
				duration := stream.EndTime - stream.StartTime
				writer.WriteString(fmt.Sprintf("Stream %d: %d packets, %d bytes, Duration: %d seconds\n",
					stream.StreamID, stream.PacketCount, stream.TotalBytes, duration))
				writer.WriteString(fmt.Sprintf("  Behavior: %s, Avg Size: %d bytes\n", 
					stream.Behavior, stream.AverageSize))
				writer.WriteString(fmt.Sprintf("  Time Range: %d - %d\n", 
					stream.StartTime, stream.EndTime))
				writer.WriteString(fmt.Sprintf("  Human Time: %s - %s\n",
					time.Unix(stream.StartTime, 0).Format("15:04:05"),
					time.Unix(stream.EndTime, 0).Format("15:04:05")))
				writer.WriteString("\n")
			}
		} else {
			writer.WriteString("No detailed stream correlation data available\n")
		}
		writer.WriteString(strings.Repeat("-", 60) + "\n\n")
	}
	
	writer.Flush()
	fmt.Printf("Detailed stream analysis saved to: %s\n", streamReportFile)
}

// generateUserFriendlyReport creates simplified report for non-technical users
func generateUserFriendlyReport(sessions []Session, reportsDir string, timestamp string) {
	simpleReportFile := filepath.Join(reportsDir, fmt.Sprintf("tor_simple_summary_%s.txt", timestamp))
	
	file, _ := os.Create(simpleReportFile)
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	writer.WriteString("TOR ACTIVITY SUMMARY - SIMPLIFIED\n")
	writer.WriteString("=================================\n\n")
	writer.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Analysis ID: %s\n\n", timestamp))
	
	writer.WriteString(fmt.Sprintf("Analysis Period: %d sessions analyzed\n\n", len(sessions)))
	
	// Overall statistics
	totalPackets := 0
	totalStreams := 0
	totalRisk := 0
	
	for _, session := range sessions {
		totalPackets += session.Packets
		totalStreams += session.Streams
		totalRisk += session.Risk
	}
	
	avgRisk := 0
	if len(sessions) > 0 {
		avgRisk = totalRisk / len(sessions)
	}
	
	writer.WriteString("OVERALL STATISTICS:\n")
	writer.WriteString("-------------------\n")
	writer.WriteString(fmt.Sprintf("Total Data Packets: %d\n", totalPackets))
	writer.WriteString(fmt.Sprintf("Total Streams: %d\n", totalStreams))
	writer.WriteString(fmt.Sprintf("Average Risk Score: %d/100\n", avgRisk))
	writer.WriteString(fmt.Sprintf("Analysis Period: From %s to %s\n\n",
		time.Unix(sessions[0].EpochTime, 0).Format("2006-01-02 15:04"),
		time.Unix(sessions[len(sessions)-1].EpochTime, 0).Format("2006-01-02 15:04")))
	
	// Activity timeline
	writer.WriteString("ACTIVITY TIMELINE:\n")
	writer.WriteString("------------------\n")
	for i, session := range sessions {
		timeStr := time.Unix(session.EpochTime, 0).Format("15:04")
		writer.WriteString(fmt.Sprintf("Session %d: %s - %d packets - %s - Risk: %d\n", 
			i+1, timeStr, session.Packets, session.Pattern, session.Risk))
	}
	
	writer.WriteString("\n")
	
	// Security assessment
	writer.WriteString("SECURITY ASSESSMENT:\n")
	writer.WriteString("--------------------\n")
	writer.WriteString(fmt.Sprintf("Overall Risk Level: %s\n", getOverallAssessment(avgRisk)))
	writer.WriteString(fmt.Sprintf("Recommendations: %s\n", getRecommendations(avgRisk, sessions)))
	
	writer.Flush()
	fmt.Printf("Simple summary saved to: %s\n", simpleReportFile)
}

// generateStreamCorrelationReport creates a very clear stream overview
func generateStreamCorrelationReport(sessions []Session, reportsDir string, timestamp string) {
	// Änderung: Zeitstempel im Dateinamen
    correlationFile := filepath.Join(reportsDir, fmt.Sprintf("tor_stream_correlation_%s.txt", timestamp))
    
    file, _ := os.Create(correlationFile)
    defer file.Close()
    
    writer := bufio.NewWriter(file)
    
    writer.WriteString("STREAM CORRELATION - WHICH PACKETS BELONG TOGETHER\n")
    writer.WriteString("===================================================\n\n")
    writer.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Analysis ID: %s\n\n", timestamp))
    
    for i, session := range sessions {
        writer.WriteString(fmt.Sprintf("SESSION %d - %s\n", i+1, 
            time.Unix(session.EpochTime, 0).Format("2006-01-02 15:04:05")))
        writer.WriteString("================================================================\n\n")
        
        if len(session.StreamData) > 0 {
            for _, stream := range session.StreamData {
                writer.WriteString(fmt.Sprintf("STREAM %d: %s ACTIVITY\n", stream.StreamID, stream.Behavior))
                writer.WriteString(fmt.Sprintf("Total Packets: %d | Total Data: %d bytes | Duration: %d seconds\n", 
                    stream.PacketCount, stream.TotalBytes, stream.EndTime-stream.StartTime))
                writer.WriteString(fmt.Sprintf("Time: %s to %s\n\n",
                    time.Unix(stream.StartTime, 0).Format("15:04:05"),
                    time.Unix(stream.EndTime, 0).Format("15:04:05")))
                
                writer.WriteString("This stream contains the following packet sequence:\n")
                writer.WriteString("Frames: ")
                
                // Show frame range clearly
                if len(stream.Packets) > 0 {
                    minFrame := stream.Packets[0].FrameNumber
                    maxFrame := stream.Packets[0].FrameNumber
                    for _, pkt := range stream.Packets {
                        if pkt.FrameNumber < minFrame {
                            minFrame = pkt.FrameNumber
                        }
                        if pkt.FrameNumber > maxFrame {
                            maxFrame = pkt.FrameNumber
                        }
                    }
                    writer.WriteString(fmt.Sprintf("%d to %d", minFrame, maxFrame))
                }
                
                writer.WriteString(fmt.Sprintf(" (%d packets in sequence)\n", stream.PacketCount))
                
                // Show what this likely represents
                writer.WriteString(fmt.Sprintf("Likely represents: %s\n\n", getStreamPurpose(stream)))
                writer.WriteString("---\n\n")
            }
        } else {
            writer.WriteString("No stream correlation data available for this session.\n\n")
        }
    }
    
    writer.Flush()
    fmt.Printf("Stream correlation report saved to: %s\n", correlationFile)
}

func getStreamPurpose(stream StreamInfo) string {
    switch stream.Behavior {
    case "UPLOAD":
        if stream.TotalBytes > 10000 {
            return "Large file upload or form submission"
        } else if stream.TotalBytes > 1000 {
            return "Medium data upload or form data"
        } else {
            return "Small request or authentication"
        }
    case "DOWNLOAD":
        if stream.TotalBytes > 50000 {
            return "Large file download or video stream"
        } else if stream.TotalBytes > 5000 {
            return "Web page with images/content"
        } else {
            return "Small response or web page text"
        }
    case "BALANCED":
        return "Interactive communication or chat"
    default:
        return "Mixed network activity"
    }
}

// getOverallAssessment returns risk assessment text
func getOverallAssessment(risk int) string {
	switch {
	case risk >= 70:
		return "HIGH - Identifiable patterns detected"
	case risk >= 50:
		return "MEDIUM - Some patterns visible" 
	case risk >= 30:
		return "LOW - Good anonymity"
	default:
		return "VERY LOW - Excellent anonymity"
	}
}

// getRecommendations provides security recommendations
func getRecommendations(avgRisk int, sessions []Session) string {
	var recommendations []string
	
	if avgRisk >= 60 {
		recommendations = append(recommendations, "Avoid large uploads/downloads")
		recommendations = append(recommendations, "Use different times for activities")
		recommendations = append(recommendations, "Mix different types of traffic")
	}
	
	if len(sessions) > 5 {
		recommendations = append(recommendations, "Multiple sessions - good for anonymity")
	}
	
	// Pattern-based recommendations
	uploadCount := 0
	for _, s := range sessions {
		if s.Pattern == "UPLOAD" {
			uploadCount++
		}
	}
	
	if uploadCount > len(sessions)/2 {
		recommendations = append(recommendations, "Frequent data sending - can be noticeable")
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Usage pattern is unnoticeable")
		recommendations = append(recommendations, "Continue good anonymity practices")
	}
	
	return strings.Join(recommendations, ", ")
}
