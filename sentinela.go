package sentinela

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/schollz/progressbar/v3"
)

// SysmonEventStats represents the statistics for a particular event.
type SysmonEventStats struct {
	Event []string // Parsed representation of the events
}

// ParseEVTX parses the given EVTX file and returns the statistics of the events as JSON format
func ParseEVTX(evtxFilePath string) (SysmonEventStats, error) {

	// Open raw EVTX file by the filename
	file, err := os.Open(evtxFilePath)
	if err != nil {
		return SysmonEventStats{}, fmt.Errorf("failed to open file %s: %v", evtxFilePath, err)
	}
	defer file.Close()

	// Using golang-evtx package, dynamically parse the given EVTX file
	ef, err := evtx.New(file)
	if err != nil {
		return SysmonEventStats{}, fmt.Errorf("failed to create EVTX parser: %v", err)
	}

	sysmonEventStats := SysmonEventStats{}

	for event := range ef.FastEvents() {

		// Jsonify parsed Sysmon EVTX log and save it to struct
		evtxJSON, err := json.Marshal(event)
		if err != nil {
			// Set an empty JSON array if marshaling fails
			log.Printf("Error marshaling JSON: %v", err)
		}

		sysmonEventStats.Event = append(sysmonEventStats.Event, string(evtxJSON))
	}

	return sysmonEventStats, nil
}

// Export the parsed EVTX to JSON
func ParseEVTXtoJSON(evtxFilePath string, exportFilePath string) {

	// Open raw EVTX file by the filename
	file, err := os.Open(evtxFilePath)
	if err != nil {
		log.Panicf("failed to open file %s: %v", evtxFilePath, err)
	}
	defer file.Close()

	// Using golang-evtx package, dynamically parse the given EVTX file
	ef, err := evtx.New(file)
	if err != nil {
		log.Panicf("failed to create EVTX parser: %v", err)
	}

	// Create a new file to write the JSON
	exportFile, err := os.Create(exportFilePath)
	if err != nil {
		log.Panicf("failed to create file %s: %v", exportFilePath, err)
	}

	bar := progressbar.Default(
		-1, // resp.ContentLength,
		"converting",
	)

	for event := range ef.FastEvents() {

		// Jsonify parsed Sysmon EVTX log and save it to struct
		evtxJSON, err := json.Marshal(event)
		if err != nil {
			// Set an empty JSON array if marshaling fails
			log.Printf("Error marshaling JSON: %v", err)
		}

		// Write the JSON to a file
		exportFile.Write(evtxJSON)
		exportFile.Write([]byte("\n"))
		bar.Add(1)

	}

}
