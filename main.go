package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/0xrawsec/golang-evtx/evtx"
)

// EventStats represents the statistics for a particular event.
type EventStats struct {
	Channel   string            // Event channel
	EventID   int64             // Event ID
	Count     int               // Number of occurrences
	EvtxJsons []json.RawMessage // Parsed JSON representation of the events
}

const sysmonEvtxFile = "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"

// evtx2json parses an EVTX file and returns statistics for events with specified IDs.
func evtx2json(evtxFile string, targetIDs []int64) ([]EventStats, error) {
	file, err := os.Open(evtxFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", evtxFile, err)
	}
	defer file.Close()

	ef, err := evtx.New(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVTX parser: %v", err)
	}

	stats := []EventStats{}

	for e := range ef.FastEvents() {
		// If targetID is not given or the current event's ID is not included in targetIDs []int64, ignore the current iteration
		if len(targetIDs) != 0 && !containsTargetEventID(e.EventID(), targetIDs) {
			continue
		}

		contains, num := containsEvent(stats, e.EventID())
		evtxJSON, err := json.Marshal(e)
		if err != nil {
			log.Printf("Error marshaling JSON: %v", err)
			evtxJSON = []byte{} // Set an empty JSON array if marshaling fails
		}

		if !contains {
			// Check if the current event ID is already included to the struct object "stats".
			// if not, create a registry for the new event.
			newStats := EventStats{e.Channel(), e.EventID(), 1, []json.RawMessage{evtxJSON}}
			stats = append(stats, newStats)
		} else {
			// Event ID already exists, increase the event by 1 and append the currently found event
			stats[num].Count++
			stats[num].EvtxJsons = append(stats[num].EvtxJsons, evtxJSON)
		}
	}

	return stats, nil
}

// containsTargetEventID checks if the event ID is in the target IDs slice.
func containsTargetEventID(eventID int64, targetIDs []int64) bool {
	for _, id := range targetIDs {
		if eventID == id {
			return true
		}
	}
	return false
}

// containsEvent checks if the event with the given ID is already present in the stats slice.
// If present, it returns true and the index; otherwise, it returns false and -1.
func containsEvent(stats []EventStats, eventID int64) (bool, int) {
	for i, stat := range stats {
		if stat.EventID == eventID {
			return true, i
		}
	}
	return false, -1
}

// ----------------------------- event ID 5 -----------------------------------
type EventData struct {
	Image       string `json:"Image"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

type Execution struct {
	ProcessID string `json:"ProcessID"`
	ThreadID  string `json:"ThreadID"`
}

type Provider struct {
	Guid string `json:"Guid"`
	Name string `json:"Name"`
}

type Security struct {
	UserID string `json:"UserID"`
}

type TimeCreated struct {
	SystemTime string `json:"SystemTime"`
}

type System struct {
	Channel       string      `json:"Channel"`
	Computer      string      `json:"Computer"`
	Correlation   interface{} `json:"Correlation"`
	EventID       string      `json:"EventID"`
	EventRecordID string      `json:"EventRecordID"`
	Execution     Execution   `json:"Execution"`
	Keywords      string      `json:"Keywords"`
	Level         string      `json:"Level"`
	Opcode        string      `json:"Opcode"`
	Provider      Provider    `json:"Provider"`
	Security      Security    `json:"Security"`
	Task          string      `json:"Task"`
	TimeCreated   TimeCreated `json:"TimeCreated"`
	Version       string      `json:"Version"`
}

type EventID5Internal struct {
	EventData EventData `json:"EventData"`
	System    System    `json:"System"`
}

type EventID5 struct {
	Event EventID5Internal `json:"Event"`
}

// ----------------------------------------------------------------------------

func main() {
	targetIDs := []int64{5} // Replace with your target event IDs

	stats, err := evtx2json(sysmonEvtxFile, targetIDs)
	if err != nil {
		log.Fatal(err)
	}

	// Display the statistics
	for _, stat := range stats {
		fmt.Printf("Channel: %s, Event ID: %d, Count: %d\n", stat.Channel, stat.EventID, stat.Count)
		for _, evtxJSON := range stat.EvtxJsons {
			fmt.Println(string(evtxJSON))
			var data EventID5
			json.Unmarshal([]byte(evtxJSON), &data)
			fmt.Println("===================================================================")
			fmt.Printf("%v\n", data.Event.EventData.Image)
			fmt.Println("===================================================================")
		}
	}
}
