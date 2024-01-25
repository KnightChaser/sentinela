# sentinela
### A simplified EVTX file parser wrapping `0xrawsec`'s `golang-evtx` module
> Parse **EVTX** file to **JSON**

## Install
```powershell
go get -u "https://github.com/KnightChaser/sentinela"
```

## Example Usage
- Import `sentinela`
- Prepare a **filepath** of target EVTX file(`*.evtx`). In case of Sysmon(System Monitor) running on Windows, the filepath will be `C:/Windows/System32/winevt/Logs/icrosoft-Windows-Sysmon%4Operational.evtx` generally.
- call `sentinela.ParseEVTX()` to parse the given EVTX file. It will return the list of JSONified text of EVTX event element in the struct `sentinela.SysmonEventStats.Event`. Because parsed data is type of `JSON`, you can easily integrate with Golang JSON module like `gjson`(Go JSON). 
```go
// SysmonEventStats represents the statistics for a particular event.
type SysmonEventStats struct {
	Event []string // Parsed representation of the events
}
```

- **Example code**
```go
package main

import (
	"fmt"
	"log"

	"github.com/KnightChaser/sentinela"
	"github.com/tidwall/gjson"
)

func main() {
    // Sysmon(System Monitor) log file in Windows
	defaultWindowsLogDirectory := "C:/Windows/System32/winevt/Logs/"
	evtxFileName := "Microsoft-Windows-Sysmon%4Operational.evtx"
	sysmonEvtxFile := fmt.Sprintf("%s%s", defaultWindowsLogDirectory, evtxFileName)

	stats, err := sentinela.ParseEVTX(sysmonEvtxFile)
	if err != nil {
		log.Fatal(err)
	}

	// Display the statistics
	for _, stat := range stats.Event {
		fmt.Println(gjson.Get(stat, "Event.System"))
		fmt.Println("=========================================================================")
	}
}
```
- **The output of example code**
```
PS C:\Users\3NR1QUE\Downloads\test> go run main.go
{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"Klojure","Correlation":{},"EventID":"10","EventRecordID":"408269","Execution":{"ProcessID":"7332","ThreadID":"9404"},"Keywords":"0x8000000000000000","Level":"4","Opcode":"0","Provider":{"Guid":"5770385F-C22A-43E0-BF4C-06F5698FFBD9","Name":"Microsoft-Windows-Sysmon"},"Security":{"UserID":"S-1-5-18"},"Task":"10","TimeCreated":{"SystemTime":"2024-01-25T03:36:31.8616887Z"},"Version":"3"}
=========================================================================
(The rest of Sysmon event will be printed as Jsonified struct...)
```

## Note
Because `sentinela` is a wrapper module of `0xrawsec`'s `golang-evtx` for simplicity, the parsed EVTX event will have a form of `golang-evtx`. It will have form like below. A single EVTX event has a struct of `Event` which has `EventData`(Vary according to the `EventID`, especially for Sysmon(System Monitor)) and `System`(The common system data for every event). FOr `sysmon`, you can take a look at `sysmonEventReference.go` for Sysmon's EVTX struct.
```json
// Parsed Sysmon EVTX file(Microsoft-Windows-Sysmon%4Operational.evtx) will look like below;
{
	"Event": {
	  "EventData": {
		  *Event-specific data...*
	  },
	  "System": {
		"Channel": *EVTX filename (ex. Microsoft-Windows-Sysmon/Operational)*,
		"Computer": *username (ex. Klojure)*,
		"Correlation": {},
		"EventID": *event type ID (integer, ex: 3)*,
		"EventRecordID": *event record ID (integer, ex: 124150)*,
		"Execution": {
		  "ProcessID": *process ID(PID) (integer, ex: 10111),
		  "ThreadID": *thread ID(TID) (integer, ex: 38476)
		},
		"Keywords": *some specific hex value, (ex. 0x8000000000000000)*,
		"Level": "4",
		"Opcode": "0",
		"Provider": {
		  "Guid": *Monitoring tool GUID (ex. 5770385F-C22A-43E0-BF4C-06F5698FFBD9)*,
		  "Name": *Monitoring tool name (ex. Microsoft-Windows-Sysmon)*
		},
		"Security": {
		  "UserID": *Security-Identifier in Windows (ex. S-1-5-18)*
		},
		"Task": "3",
		"TimeCreated": {
		  "SystemTime": *Log creation date (ex. 2024-01-24T07:10:28.4951317Z)*
		},
		"Version": "5"
	  }
	}
}
```

## (TIP) Install Sysmon
- Go to official Sysinternals webpage and download Sysmon<br>
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Prepare your own `config.xml` for Sysmon or use recommended Sysmon modular configuration file
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile C:\Windows\config.xml
```
- Start Sysmon with the prepared configuration file.
```powershell
./Sysmon64.exe –accepteula –i C:\Windows\config.xml   # 64 bits
./Sysmon.exe -accepteula -i C:\Windows\config.xml     # 32 bits
```