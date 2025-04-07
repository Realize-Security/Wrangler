package models

import "encoding/xml"

// NmapRun is the top-level element <nmaprun>.
type NmapRun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            string   `xml:"start,attr"`
	StartStr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	XMLOutputVersion string   `xml:"xmloutputversion,attr"`

	ScanInfo  []ScanInfo `xml:"scaninfo"`
	Verbose   Verbose    `xml:"verbose"`
	Debugging Debugging  `xml:"debugging"`
	Hosts     []Host     `xml:"host"`
	RunStats  RunStats   `xml:"runstats"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type Verbose struct {
	Level string `xml:"level,attr"`
}

type Debugging struct {
	Level string `xml:"level,attr"`
}

// Each Host block in the XML is represented by <host>.
type Host struct {
	StartTime string    `xml:"starttime,attr"`
	EndTime   string    `xml:"endtime,attr"`
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`   // In XML, there can be multiple <address> elements
	HostNames HostNames `xml:"hostnames"` // <hostnames> can contain multiple <hostname> elements
	Ports     Ports     `xml:"ports"`
	Times     Times     `xml:"times"` // Optional, sometimes not present depending on Nmap version/options
}

type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// HostNames is the container for zero or more <hostname> entries.
type HostNames struct {
	HostName []HostName `xml:"hostname"`
}

type HostName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports wraps both <extraports> (if present) and multiple <port> entries.
type Ports struct {
	ExtraPorts []ExtraPorts `xml:"extraports"`
	Port       []Port       `xml:"port"`
}

// ExtraPorts models <extraports state="filtered" count="65522"> … </extraports>.
type ExtraPorts struct {
	State        string         `xml:"state,attr"`
	Count        string         `xml:"count,attr"`
	ExtraReasons []ExtraReasons `xml:"extrareasons"`
}

type ExtraReasons struct {
	Reason string `xml:"reason,attr"`
	Count  string `xml:"count,attr"`
}

// Port corresponds to <port protocol="tcp" portid="80"> … </port>.
type Port struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   string    `xml:"portid,attr"`
	State    PortState `xml:"state"`
	Service  Service   `xml:"service"`
}

// PortState is the <state state="open" reason="…" reason_ttl="…"/>
type PortState struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

// Service corresponds to the <service> element inside each <port>.
// Some attributes (e.g., product, servicefp, tunnel) may or may not appear.
type Service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	ServiceFP string `xml:"servicefp,attr"`
	Tunnel    string `xml:"tunnel,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
	// The <cpe> element is optional and may appear once inside <service>
	CPE string `xml:"cpe,omitempty"`
}

// Times is an optional block like: <times srtt="…" rttvar="…" to="…" />
type Times struct {
	Srtt   string `xml:"srtt,attr"`
	Rttvar string `xml:"rttvar,attr"`
	To     string `xml:"to,attr"`
}

// RunStats is <runstats> at the bottom, which contains <finished> and <hosts>.
type RunStats struct {
	Finished Finished    `xml:"finished"`
	Hosts    HostsStruct `xml:"hosts"`
}

type Finished struct {
	Time    string `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed string `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

type HostsStruct struct {
	Up    string `xml:"up,attr"`
	Down  string `xml:"down,attr"`
	Total string `xml:"total,attr"`
}
