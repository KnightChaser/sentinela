package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/valyala/fastjson"
)

// EventStats represents the statistics for a particular event.
type SysmonEventStats struct {
	Channel          string           // Event channel
	EventID          int64            // Event ID
	Count            int              // Number of occurrences
	sysmonEvtxStruct []fastjson.Value // Parsed representation of the events
}

func parseSysmonEVTX(evtxFile string) ([]SysmonEventStats, error) {
	file, err := os.Open(evtxFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", evtxFile, err)
	}
	defer file.Close()

	ef, err := evtx.New(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create EVTX parser: %v", err)
	}

	sysmonEventStats := []SysmonEventStats{}

	for e := range ef.FastEvents() {

		contains, num := containsEvent(sysmonEventStats, e.EventID())

		// Jsonify parsed Sysmon EVTX log and save it to struct
		evtxJSON, err := json.Marshal(e)
		if err != nil {
			// Set an empty JSON array if marshaling fails
			log.Printf("Error marshaling JSON: %v", err)
		}

		// dynamically parse JSON
		var fastjsonParser fastjson.Parser
		p, err := fastjsonParser.Parse(string(evtxJSON))
		parsedEvtxJSON := *p

		if !contains {
			// Check if the current event ID is already included to the struct object "stats".
			// if not, create a registry for the new event.
			newSysmonEventStats := SysmonEventStats{e.Channel(), e.EventID(), 1, []fastjson.Value{parsedEvtxJSON}}
			sysmonEventStats = append(sysmonEventStats, newSysmonEventStats)
		} else {
			// Event ID already exists, increase the event by 1 and append the currently found event
			sysmonEventStats[num].Count++
			sysmonEventStats[num].sysmonEvtxStruct = append(sysmonEventStats[num].sysmonEvtxStruct, parsedEvtxJSON)
		}
	}

	return sysmonEventStats, nil
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
func containsEvent(stats []SysmonEventStats, eventID int64) (bool, int) {
	for i, stat := range stats {
		if stat.EventID == eventID {
			return true, i
		}
	}
	return false, -1
}

func main() {

	defaultWindowsLogDirectory := "C:/Windows/System32/winevt/Logs/"
	evtxFileName := "Microsoft-Windows-Sysmon%4Operational.evtx"
	sysmonEvtxFile := fmt.Sprintf("%s%s", defaultWindowsLogDirectory, evtxFileName)

	stats, err := parseSysmonEVTX(sysmonEvtxFile)
	if err != nil {
		log.Fatal(err)
	}

	// Display the statistics
	for _, stat := range stats {
		fmt.Printf("Channel: %s, Event ID: %d, Count: %d\n", stat.Channel, stat.EventID, stat.Count)
		for _, sysmonEventStruct := range stat.sysmonEvtxStruct {
			eventID, _ := strconv.Atoi(string(sysmonEventStruct.GetStringBytes("Event", "System", "EventID")))
			fmt.Println(eventID)
		}
	}
}
