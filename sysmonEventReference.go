package sentinela

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
// }

// ------------------------------- Sysmon System Struct (Common for all event ID) ----------------------------------------

type Execution struct {
	ProcessID uint32 `json:"ProcessID"`
	ThreadID  uint32 `json:"ThreadID"`
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

// System struct is commonly shared by all events
type System struct {
	Channel       string      `json:"Channel"`
	Computer      string      `json:"Computer"`
	Correlation   interface{} `json:"Correlation"`
	EventID       uint32      `json:"EventID"`
	EventRecordID uint32      `json:"EventRecordID"`
	Execution     Execution   `json:"Execution"`
	Keywords      string      `json:"Keywords"`
	Level         uint32      `json:"Level"`
	Opcode        uint32      `json:"Opcode"`
	Provider      Provider    `json:"Provider"`
	Security      Security    `json:"Security"`
	Task          uint32      `json:"Task"`
	TimeCreated   TimeCreated `json:"TimeCreated"`
	Version       uint32      `json:"Version"`
}

// ------------------------------- Sysmon Event Struct (By event ID, for reference) -------------------------------
// ID 1. Process Create
type EventDataID1 struct {
	CommandLine       string `json:"CommandLine"`
	Company           string `json:"Company"`
	CurrentDirectory  string `json:"CurrentDirectory"`
	Description       string `json:"Description"`
	FileVersion       string `json:"FileVersion"`
	Hashes            string `json:"Hashes"`
	Image             string `json:"Image"`
	IntegrityLevel    string `json:"IntegrityLevel"`
	LogonGuid         string `json:"LogonGuid"`
	LogonId           string `json:"LogonId"`
	OriginalFileName  string `json:"OriginalFileName"`
	ParentCommandLine string `json:"ParentCommandLine"`
	ParentImage       string `json:"ParentImage"`
	ParentProcessGuid string `json:"ParentProcessGuid"`
	ParentProcessId   string `json:"ParentProcessId"`
	ParentUser        string `json:"ParentUser"`
	ProcessGuid       string `json:"ProcessGuid"`
	ProcessId         string `json:"ProcessId"`
	Product           string `json:"Product"`
	RuleName          string `json:"RuleName"`
	TerminalSessionId string `json:"TerminalSessionId"`
	User              string `json:"User"`
	UtcTime           string `json:"UtcTime"`
}

// ID 2. File creation time changed
type EventDataID2 struct {
	CreationUtcTime         string `json:"CreationUtcTime"`
	Image                   string `json:"Image"`
	PreviousCreationUtcTime string `json:"PreviousCreationUtcTime"`
	ProcessGuid             string `json:"ProcessGuid"`
	ProcessId               string `json:"ProcessId"`
	RuleName                string `json:"RuleName"`
	TargetFilename          string `json:"TargetFilename"`
	User                    string `json:"User"`
	UtcTime                 string `json:"UtcTime"`
}

// ID 3. Network connection detected
type EventDataID3 struct {
	DestinationHostname string `json:"DestinationHostname"`
	DestinationIp       string `json:"DestinationIp"`
	DestinationIsIpv6   string `json:"DestinationIsIpv6"`
	DestinationPort     string `json:"DestinationPort"`
	DestinationPortName string `json:"DestinationPortName"`
	Image               string `json:"Image"`
	Initiated           string `json:"Initiated"`
	ProcessGuid         string `json:"ProcessGuid"`
	ProcessId           string `json:"ProcessId"`
	Protocol            string `json:"Protocol"`
	RuleName            string `json:"RuleName"`
	SourceHostname      string `json:"SourceHostname"`
	SourceIp            string `json:"SourceIp"`
	SourceIsIpv6        string `json:"SourceIsIpv6"`
	SourcePort          string `json:"SourcePort"`
	SourcePortName      string `json:"SourcePortName"`
	User                string `json:"User"`
	UtcTime             string `json:"UtcTime"`
}

// ID 4. Sysmon service state changed
type EventDataID4 struct {
	SchemaVersion string `json:"SchemaVersion"`
	State         string `json:"State"`
	UtcTime       string `json:"UtcTime"`
	Version       string `json:"Version"`
}

// ID 5. Process terminated
type EventDataID5 struct {
	Image       string `json:"Image"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ID 6. Driver loaded
type EventDataID6 struct {
	Hashs           string `json:"Hashes"`
	ImageLoaded     string `json:"ImageLoaded"`
	RuleName        string `json:"RuleName"`
	Signature       string `json:"Signature"`
	SignatureStatus string `json:"SignatureStatus"`
	Signed          string `json:"Signed"`
	UtcTime         string `json:"UtcTime"`
}

// ID 7. Image loaded
type EventDataID7 struct {
	Company          string `json:"Company"`
	Description      string `json:"Description"`
	FileVersion      string `json:"FileVersion"`
	Hashes           string `json:"Hashes"`
	Image            string `json:"Image"`
	ImageLoaded      string `json:"ImageLoaded"`
	OriginalFileName string `json:"OriginalFileName"`
	ProcessGuid      string `json:"ProcessGuid"`
	ProcessId        string `json:"ProcessId"`
	Product          string `json:"Product"`
	RuleName         string `json:"RuleName"`
	Signature        string `json:"Signature"`
	SignatureStatus  string `json:"SignatureStatus"`
	Signed           string `json:"Signed"`
	User             string `json:"User"`
	UtcTime          string `json:"UtcTime"`
}

// ID 8. CreateRemoteTread detected
type EventDataID8 struct {
	NewThreadId       string `json:"NewThreadId"`
	RuleName          string `json:"RuleName"`
	SourceImage       string `json:"SourceImage"`
	SourceProcessGuid string `json:"SourceProcessGuid"`
	SourceProcessId   string `json:"SourceProcessId"`
	SourceUser        string `json:"SourceUser"`
	StartAddress      string `json:"StartAddress"`
	StartFunction     string `json:"StartFunction"`
	StartModule       string `json:"StartModule"`
	TargetImage       string `json:"TargetImage"`
	TargetProcessGuid string `json:"TargetProcessGuid"`
	TargetProcessId   string `json:"TargetProcessId"`
	TargetUser        string `json:"TargetUser"`
	UtcTime           string `json:"UtcTime"`
}

// ID 9. RawAccessRead detected
type EventDataID9 struct {
	Device      string `json:"Device"`
	Image       string `json:"Image"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ID 10. Process accessed
type EventDataID10 struct {
	CallTrace         string `json:"CallTrace"`
	GrantedAccess     string `json:"GrantedAccess"`
	RuleName          string `json:"RuleName"`
	SourceImage       string `json:"SourceImage"`
	SourceProcessGUID string `json:"SourceProcessGUID"`
	SourceProcessId   string `json:"SourceProcessId"`
	SourceThreadId    string `json:"SourceThreadId"`
	SourceUser        string `json:"SourceUser"`
	TargetImage       string `json:"TargetImage"`
	TargetProcessGUID string `json:"TargetProcessGUID"`
	TargetProcessId   string `json:"TargetProcessId"`
	TargetUser        string `json:"TargetUser"`
	UtcTime           string `json:"UtcTime"`
}

// ID 11. File created
type EventDataID11 struct {
	CreationUtcTime string `json:"CreationUtcTime"`
	Image           string `json:"Image"`
	ProcessGuid     string `json:"ProcessGuid"`
	ProcessId       string `json:"ProcessId"`
	RuleName        string `json:"RuleName"`
	TargetFilename  string `json:"TargetFilename"`
	User            string `json:"User"`
	UtcTime         string `json:"UtcTime"`
}

// ID 12. RegistryEvent, Object added or deleted
type EventDataID12 struct {
	EventType    string `json:"EventType"`
	Image        string `json:"Image"`
	ProcessGuid  string `json:"ProcessGuid"`
	ProcessId    string `json:"ProcessId"`
	RuleName     string `json:"RuleName"`
	TargetObject string `json:"TargetObject"`
	User         string `json:"User"`
	UtcTime      string `json:"UtcTime"`
}

// ID 13. RegistryEvent, Value set
type EventDataID13 struct {
	Details      string `json:"Details"`
	EventType    string `json:"EventType"`
	Image        string `json:"Image"`
	ProcessGuid  string `json:"ProcessGuid"`
	ProcessId    string `json:"ProcessId"`
	RuleName     string `json:"RuleName"`
	TargetObject string `json:"TargetObject"`
	User         string `json:"User"`
	UtcTime      string `json:"UtcTime"`
}

// ID 14. RegistryEvent, Object renamed
type EventDataID14 struct {
	EventType    string `json:"EventType"`
	Image        string `json:"Image"`
	NewName      string `json:"NewName"`
	ProcessGuid  string `json:"ProcessGuid"`
	ProcessId    string `json:"ProcessId"`
	RuleName     string `json:"RuleName"`
	TargetObject string `json:"TargetObject"`
	User         string `json:"User"`
	UtcTime      string `json:"UtcTime"`
}

// ID 15. File stream created
type EventDataID15 struct {
	Contents        string `json:"Contents"`
	CreationUtcTime string `json:"CreationUtcTime"`
	Hash            string `json:"Hash"`
	Image           string `json:"Image"`
	ProcessGuid     string `json:"ProcessGuid"`
	ProcessId       string `json:"ProcessId"`
	RuleName        string `json:"RuleName"`
	TargetFilename  string `json:"TargetFilename"`
	User            string `json:"User"`
	UtcTime         string `json:"UtcTime"`
}

// ID 16. Sysmon config state changed
type EventDataID16 struct {
	Configuration         string `json:"Configuration"`
	ConfigurationFileHash string `json:"ConfigurationFileHash"`
	UtcTime               string `json:"UtcTime"`
}

// ID 17. PipeEvent, Pipe Created
type EventDataID17 struct {
	EventType   string `json:"EventType"`
	Image       string `json:"Image"`
	PipeName    string `json:"PipeName"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ID 18. PipeEvent, Pipe Connected
type EventDataID18 struct {
	EventType   string `json:"EventType"`
	Image       string `json:"Image"`
	PipeName    string `json:"PipeName"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ID 19. WmiEvent, WmiEventFilter activity detected
type EventDataID19 struct {
	EventNamespace string `json:"EventNamespace"`
	EventType      string `json:"EventType"`
	Name           string `json:"Name"`
	Operation      string `json:"Operation"`
	Query          string `json:"Query"`
	RuleName       string `json:"RuleName"`
	User           string `json:"User"`
	UtcTime        string `json:"UtcTime"`
}

// ID 20. WmiEvent, WmiEventConsumer activity detected
type EventDataID20 struct {
	Destination string `json:"Destination"`
	EventType   string `json:"EventType"`
	Name        string `json:"Name"`
	Operation   string `json:"Operation"`
	RuleName    string `json:"RuleName"`
	Type        string `json:"Type"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ID 21. WmiEvent, WmiEventConsumerToFilter activity detected
type EventDataID21 struct {
	Consumer  string `json:"Consumer"`
	EventType string `json:"EventType"`
	Filter    string `json:"Filter"`
	Operation string `json:"Operation"`
	RuleName  string `json:"RuleName"`
	User      string `json:"User"`
	UtcTime   string `json:"UtcTime"`
}

// ID 22. DNSEvent, DNS query
type EventDataID22 struct {
	Image        string `json:"Image"`
	ProcessGuid  string `json:"ProcessGuid"`
	ProcessId    string `json:"ProcessId"`
	QueryName    string `json:"QueryName"`
	QueryResults string `json:"QueryResults"`
	QueryStatus  string `json:"QueryStatus"`
	RuleName     string `json:"RuleName"`
	User         string `json:"User"`
	UtcTime      string `json:"UtcTime"`
}

// ID 23. FileDelete, File Delete archived
type EventDataID23 struct {
	Archived       string `json:"Archived"`
	Hashes         string `json:"Hashes"`
	Image          string `json:"Image"`
	IsExecutable   string `json:"IsExecutable"`
	ProcessGuid    string `json:"ProcessGuid"`
	ProcessId      string `json:"ProcessId"`
	RuleName       string `json:"RuleName"`
	TargetFilename string `json:"TargetFilename"`
	User           string `json:"User"`
	UtcTime        string `json:"UtcTime"`
}

// ID 24. Clipboard changed
type EventDataID24 struct {
	Archived    string `json:"Archived"`
	ClientInfo  string `json:"ClientInfo"`
	Hashes      string `json:"Hashes"`
	Image       string `json:"Image"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	RuleName    string `json:"RuleName"`
	Session     string `json:"Session"`
	User        string `json:"User"`
	UtcTime     string `json:"UtcTime"`
}

// ID 25. Process Tampering
type EventDataID25 struct {
	RuleName    string `json:"RuleName"`
	UtcTime     string `json:"UtcTime"`
	ProcessGuid string `json:"ProcessGuid"`
	ProcessId   string `json:"ProcessId"`
	Image       string `json:"Image"`
	Type        string `json:"Type"`
	User        string `json:"User"`
}

// ID 26. File Delete logged
type EventDataID26 struct {
	Hashes         string `json:"Hashes"`
	Image          string `json:"Image"`
	IsExecutable   string `json:"IsExecutable"`
	ProcessGuid    string `json:"ProcessGuid"`
	ProcessId      string `json:"ProcessId"`
	RuleName       string `json:"RuleName"`
	TargetFilename string `json:"TargetFilename"`
	User           string `json:"User"`
	UtcTime        string `json:"UtcTime"`
}

// ID 27. File Block Executable
type EventDataID27 struct {
	RuleName       string `json:"RuleName"`
	UtcTime        string `json:"UtcTime"`
	ProcessGuid    string `json:"ProcessGuid"`
	ProcessId      string `json:"ProcessId"`
	User           string `json:"User"`
	Image          string `json:"Image"`
	TargetFilename string `json:"TargetFilename"`
	Hashes         string `json:"Hashes"`
}

// ID 28. File Block Shredding
type EventDataID28 struct {
	RuleName       string `json:"RuleName"`
	UtcTime        string `json:"UtcTime"`
	ProcessGuid    string `json:"ProcessGuid"`
	ProcessId      string `json:"ProcessId"`
	User           string `json:"User"`
	Image          string `json:"Image"`
	TargetFilename string `json:"TargetFilename"`
	Hashes         string `json:"Hashes"`
	IsExecutable   string `json:"IsExecutable"`
}

// ----------------------------------------------------------------------------------------------------------------

type EventInternal struct {
	EventData map[string]string `json:"EventData"` // save event data dynamically according to the ID of Sysmon event
	System    System            `json:"System"`
}

// Event represents the Sysmon event.
type Event struct {
	Event EventInternal `json:"Event"`
}
