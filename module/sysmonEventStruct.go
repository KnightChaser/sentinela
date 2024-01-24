package sysmonEventStruct

// Sysmon event struct (from golang-evtx)

// {
// 	"Event": {
// 	  "EventData": {
// 		  *Event-specific data...*
// 	  },
// 	  "System": {
// 		"Channel": *EVTX filename (ex. Microsoft-Windows-Sysmon/Operational)*,
// 		"Computer": *username (ex. Klojure)*,
// 		"Correlation": {},
// 		"EventID": *event type ID (integer, ex: 3)*,
// 		"EventRecordID": *event record ID (integer, ex: 124150)*,
// 		"Execution": {
// 		  "ProcessID": *process ID(PID) (integer, ex: 10111),
// 		  "ThreadID": *thread ID(TID) (integer, ex: 38476)
// 		},
// 		"Keywords": *some specific hex value, (ex. 0x8000000000000000)*,
// 		"Level": "4",
// 		"Opcode": "0",
// 		"Provider": {
// 		  "Guid": *Monitoring tool GUID (ex. 5770385F-C22A-43E0-BF4C-06F5698FFBD9)*,
// 		  "Name": *Monitoring tool name (ex. Microsoft-Windows-Sysmon)*
// 		},
// 		"Security": {
// 		  "UserID": *Security-Identifier in Windows (ex. S-1-5-18)*
// 		},
// 		"Task": "3",
// 		"TimeCreated": {
// 		  "SystemTime": *Log creation date (ex. 2024-01-24T07:10:28.4951317Z)*
// 		},
// 		"Version": "5"
// 	  }
// 	}
//   }

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

// ------------------------------ EventData struct (different according to event ID) ------------------------------

type EventDataID5 struct {
	Image       string `json:"Image"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ----------------------------------------------------------------------------------------------------------------

type EventID5Internal struct {
	EventData EventDataID5 `json:"EventData"`
	System    System       `json:"System"`
}

type EventID5 struct {
	Event EventID5Internal `json:"Event"`
}
