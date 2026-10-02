package ipmi

import (
	"regexp"
	"strings"

	"github.com/nguyenquocanhz/diagward/model"
)

// Sensor classes. A class decides the report component and the wording.
const (
	clTemp      = "temperature"
	clFan       = "fan"
	clVoltage   = "voltage"
	clCurrent   = "current"
	clPower     = "power" // watts
	clPSU       = "psu"
	clPowerUnit = "power-unit" // PSU redundancy / whole-system power
	clMemory    = "memory"
	clCPU       = "cpu"
	clDisk      = "disk"
	clIntrusion = "intrusion"
	clBattery   = "battery"
	clWatchdog  = "watchdog"
	clBMC       = "bmc"
	clSystem    = "system"
	clOther     = "other"
)

func classComponent(cl string) string {
	switch cl {
	case clTemp:
		return model.CompThermal
	case clFan:
		return model.CompFan
	case clVoltage, clCurrent, clPower, clPSU, clPowerUnit:
		return model.CompPower
	case clMemory:
		return model.CompMemory
	case clCPU:
		return model.CompCPU
	case clDisk:
		return model.CompDisk
	case clBMC:
		return model.CompBMC
	}
	return model.CompSystem
}

// rule maps one IPMI state / event description (as ipmitool prints it, see
// ipmitool include/ipmitool/ipmi_sel.h: generic_event_types and
// sensor_specific_event_types) to a severity. Matching is on the lowercase
// text without the parenthesised OEM details ipmitool >= 1.8.19 appends.
type rule struct {
	match string // lowercase substring (or exact text when exact is set)
	exact bool
	sev   model.Severity
	key   string // finding key; "*" = derived from the sensor class
	comp  string // component override
}

// Order matters: more specific texts first ("uncorrectable ecc" before
// "correctable ecc", "redundancy degraded from fully redundant" before
// "fully redundant").
//
// Severity follows the contract: a failed or input-less PSU, failed fan,
// uncorrectable ECC, fatal CPU/bus errors and failed drives/arrays are
// Crit; redundancy lost, corrected-error limits, predictive failures,
// intrusion and configuration errors are Warn.
var rules = []rule{
	// memory
	{match: "uncorrectable ecc", sev: model.Crit, key: "memory_ue", comp: model.CompMemory},
	{match: "correctable ecc logging limit reached", sev: model.Warn, key: "memory_ce", comp: model.CompMemory},
	{match: "correctable memory error logging disabled", sev: model.Warn, key: "memory_ce", comp: model.CompMemory},
	{match: "correctable ecc", sev: model.Warn, key: "memory_ce", comp: model.CompMemory},
	{match: "memory scrub failed", sev: model.Crit, key: "memory_ue", comp: model.CompMemory},
	{match: "memory device disabled", sev: model.Crit, key: "memory_disabled", comp: model.CompMemory},
	{match: "critical overtemperature", sev: model.Crit, key: "memory_overtemp", comp: model.CompMemory},
	{match: "parity", exact: true, sev: model.Crit, key: "memory_ue", comp: model.CompMemory},
	// processor
	{match: "uncorrectable machine check", sev: model.Crit, key: "cpu_error", comp: model.CompCPU},
	{match: "sm bios uncorrectable cpu-complex error", sev: model.Crit, key: "cpu_error", comp: model.CompCPU},
	{match: "ierr", exact: true, sev: model.Crit, key: "cpu_error", comp: model.CompCPU},
	{match: "frb1/bist failure", sev: model.Crit, key: "cpu_error", comp: model.CompCPU},
	{match: "frb2/hang in post failure", sev: model.Crit, key: "cpu_error", comp: model.CompCPU},
	{match: "frb3/processor startup/init failure", sev: model.Crit, key: "cpu_error", comp: model.CompCPU},
	{match: "correctable machine check error", sev: model.Warn, key: "cpu_ce", comp: model.CompCPU},
	{match: "thermal trip", sev: model.Crit, key: "thermal_trip", comp: model.CompThermal},
	// power supplies
	{match: "power supply ac lost", sev: model.Crit, key: "psu_ac_lost", comp: model.CompPower},
	{match: "ac lost or out-of-range", sev: model.Crit, key: "psu_ac_lost", comp: model.CompPower},
	{match: "ac out-of-range, but present", sev: model.Warn, key: "psu_ac_lost", comp: model.CompPower},
	{match: "power supply inactive", sev: model.Info, key: "psu_inactive", comp: model.CompPower},
	{match: "predictive failure deasserted", sev: model.OK},
	{match: "failure detected", sev: model.Crit, key: "*failed"},
	{match: "predictive failure", sev: model.Warn, key: "*predictive"},
	{match: "config error", sev: model.Warn, key: "config_error"},
	{match: "configuration error", sev: model.Warn, key: "config_error"},
	{match: "install error", sev: model.Warn, key: "config_error"},
	// redundancy (PSU or fan sets)
	{match: "non-redundant: insufficient resources", sev: model.Crit, key: "redundancy_lost"},
	{match: "redundancy degraded", sev: model.Warn, key: "redundancy_lost"},
	{match: "redundancy lost", sev: model.Warn, key: "redundancy_lost"},
	{match: "non-redundant", sev: model.Warn, key: "redundancy_lost"},
	{match: "fully redundant", sev: model.OK},
	// drives
	{match: "drive fault", sev: model.Crit, key: "drive_fault", comp: model.CompDisk},
	{match: "in failed array", sev: model.Crit, key: "raid_failed", comp: model.CompRAID},
	{match: "in critical array", sev: model.Crit, key: "raid_failed", comp: model.CompRAID},
	{match: "rebuild aborted", sev: model.Warn, key: "raid_rebuild", comp: model.CompRAID},
	{match: "rebuild in progress", sev: model.Info, key: "raid_rebuild", comp: model.CompRAID},
	// chassis intrusion: Warn, the switch latches until cleared
	{match: "intrusion", sev: model.Warn, key: "intrusion", comp: model.CompSystem},
	// buses
	{match: "bus uncorrectable error", sev: model.Crit, key: "pci_error", comp: model.CompSystem},
	{match: "bus fatal error", sev: model.Crit, key: "pci_error", comp: model.CompSystem},
	{match: "fatal nmi", sev: model.Crit, key: "pci_error", comp: model.CompSystem},
	{match: "pci serr", sev: model.Crit, key: "pci_error", comp: model.CompSystem},
	{match: "pci perr", sev: model.Crit, key: "pci_error", comp: model.CompSystem},
	{match: "i/o channel check nmi", sev: model.Crit, key: "pci_error", comp: model.CompSystem},
	{match: "bus correctable error", sev: model.Warn, key: "pci_error", comp: model.CompSystem},
	{match: "bus degraded", sev: model.Warn, key: "pci_error", comp: model.CompSystem},
	// generic severity transitions (HPE "Fan 1 | Transition to OK")
	{match: "transition to critical from less severe", sev: model.Crit, key: "*state"},
	{match: "transition to critical from non-recoverable", sev: model.Crit, key: "*state"},
	{match: "transition to non-recoverable", sev: model.Crit, key: "*state"},
	{match: "transition to non-critical", sev: model.Warn, key: "*state"},
	{match: "transition to degraded", sev: model.Warn, key: "*state"},
	{match: "limit exceeded", sev: model.Warn, key: "*state"},
	{match: "performance lags", sev: model.Warn, key: "*state"},
	// threshold events in the SEL
	{match: "upper non-recoverable going high", sev: model.Crit, key: "*threshold"},
	{match: "lower non-recoverable going low", sev: model.Crit, key: "*threshold"},
	{match: "upper critical going high", sev: model.Crit, key: "*threshold"},
	{match: "lower critical going low", sev: model.Crit, key: "*threshold"},
	{match: "upper non-critical going high", sev: model.Warn, key: "*threshold"},
	{match: "lower non-critical going low", sev: model.Warn, key: "*threshold"},
	// whole-system power
	{match: "ac lost", exact: true, sev: model.Warn, key: "ac_lost", comp: model.CompPower},
	{match: "soft-power control failure", sev: model.Warn, key: "power_control", comp: model.CompPower},
	{match: "soft power control failure", sev: model.Warn, key: "power_control", comp: model.CompPower},
	{match: "interlock power down", sev: model.Warn, key: "power_control", comp: model.CompPower},
	{match: "240va power down", sev: model.Warn, key: "power_control", comp: model.CompPower},
	// OS / firmware
	{match: "run-time critical stop", sev: model.Warn, key: "os_crash", comp: model.CompSystem},
	{match: "error during system startup", sev: model.Warn, key: "os_crash", comp: model.CompSystem},
	{match: "linux kernel panic", sev: model.Warn, key: "os_crash", comp: model.CompSystem},
	{match: "undetermined system hardware failure", sev: model.Warn, key: "hw_failure", comp: model.CompSystem},
	{match: "unrecoverable", sev: model.Warn, key: "post_error", comp: model.CompSystem},
	{match: "no system memory installed", sev: model.Warn, key: "post_error", comp: model.CompMemory},
	{match: "no usable system memory", sev: model.Warn, key: "post_error", comp: model.CompMemory},
	{match: "bios corruption detected", sev: model.Warn, key: "post_error", comp: model.CompSystem},
	{match: "cpu voltage mismatch", sev: model.Warn, key: "post_error", comp: model.CompCPU},
	{match: "cpu speed mismatch", sev: model.Warn, key: "post_error", comp: model.CompCPU},
	{match: "throttled", sev: model.Warn, key: "throttled"},
	// event log
	{match: "log full", exact: true, sev: model.Warn, key: "sel_full", comp: model.CompBMC},
	{match: "all event logging disabled", sev: model.Warn, key: "sel_full", comp: model.CompBMC},
	{match: "event logging disabled", sev: model.Warn, key: "sel_full", comp: model.CompBMC},
	{match: "log almost full", sev: model.Info, key: "sel_full", comp: model.CompBMC},
	{match: "log area reset/cleared", sev: model.Info, key: "sel_cleared", comp: model.CompBMC},
	// presence
	{match: "device absent", sev: model.Info, key: "*absent"},
	{match: "absent", exact: true, sev: model.Info, key: "*absent"},
	// battery sensor type (0x29): "Low", "Failed"
	{match: "low", exact: true, sev: model.Warn, key: "battery"},
	{match: "failed", exact: true, sev: model.Warn, key: "battery"},
}

var parenRe = regexp.MustCompile(`\s*\(.*\)\s*$`)

// normEvent lowercases an event text and drops ipmitool's trailing
// "(OEM details)" so "Failure detected ()" matches "failure detected".
func normEvent(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "("); i > 0 {
		s = s[:i]
	}
	s = parenRe.ReplaceAllString(s, "")
	return strings.ToLower(strings.TrimSpace(s))
}

// verdict is what a rule says about one state in one sensor class.
type verdict struct {
	sev  model.Severity
	key  string
	comp string
	ok   bool // a rule matched
}

func judge(text, class, sensorName string) verdict {
	n := normEvent(text)
	if n == "" {
		return verdict{}
	}
	for _, r := range rules {
		if (r.exact && n != r.match) || (!r.exact && !strings.Contains(n, r.match)) {
			continue
		}
		v := verdict{sev: r.sev, key: r.key, comp: r.comp, ok: true}
		if r.key == "battery" && class != clBattery {
			return verdict{} // "Low"/"Failed" only mean something on a battery sensor
		}
		if strings.HasPrefix(v.key, "*") {
			v.key = classKey(class, v.key[1:])
		}
		if v.comp == "" {
			v.comp = classComponent(class)
		}
		if v.key == "intrusion" {
			v.comp = model.CompSystem
		}
		return v
	}
	// "State Asserted" is generic; on Dell the "... PG" (power good) and
	// "... FAIL" sensors use it for faults, elsewhere it can mean anything.
	if n == "state asserted" {
		l := strings.ToLower(sensorName)
		if strings.Contains(l, "fail") || strings.Contains(l, "fault") || strings.HasSuffix(l, " pg") || strings.Contains(l, " pg ") {
			return verdict{sev: model.Warn, key: "state_asserted", comp: classComponent(class), ok: true}
		}
		return verdict{sev: model.Info, key: "state_asserted", comp: classComponent(class), ok: true}
	}
	if class == clWatchdog && n != "timer interrupt" {
		return verdict{sev: model.Warn, key: "watchdog", comp: model.CompSystem, ok: true}
	}
	return verdict{}
}

// classKey builds keys like psu_failed, fan_failed, drive_predictive.
func classKey(class, what string) string {
	p := map[string]string{
		clPSU: "psu", clPowerUnit: "power", clFan: "fan", clDisk: "drive", clMemory: "memory",
		clCPU: "cpu", clTemp: "temperature", clVoltage: "voltage", clCurrent: "current", clPower: "power",
		clBattery: "battery", clBMC: "bmc",
	}[class]
	if p == "" {
		p = "device"
	}
	if what == "state" || what == "threshold" {
		return "sensor_" + p
	}
	return p + "_" + what
}

// psuNameRe recognises power supply sensor / FRU names across vendors:
// Dell "PS1 Status", HPE "Power Supply 1", Supermicro "PS2 Status",
// Lenovo "PSU1 IN Failure", HPE "41-P/S 1", Intel "PS1 Status".
var psuNameRe = regexp.MustCompile(`(?i)(^|[^a-z])(ps|psu|pws|p/s|pwr supply|power supply)\s*_?([0-9]+)`)

func psuNumber(name string) int {
	m := psuNameRe.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	n := 0
	for _, c := range m[3] {
		n = n*10 + int(c-'0')
		if n > 99 {
			return 0
		}
	}
	return n
}

// classify guesses a sensor class from the units, the entity ID (IPMI 2.0
// table 43-13: 3 processor, 4 disk bay, 7 system board, 8 memory module,
// 10 power supply, 19 power unit, 26 disk drive bay, 29 fan, 30 cooling
// unit, 32 memory device, 55 air inlet), the name and the states.
func classify(name string, entityID int, unit string, states []string) string {
	switch strings.ToLower(unit) {
	case "degrees c", "degrees f", "degrees k":
		return clTemp
	case "rpm":
		return clFan
	case "volts":
		return clVoltage
	case "amps":
		return clCurrent
	case "watts":
		if entityID == 10 || psuNumber(name) > 0 {
			return clPSU
		}
		return clPower
	case "percent", "cfm":
		if strings.Contains(strings.ToLower(name), "fan") || entityID == 29 || entityID == 30 {
			return clFan
		}
		return clOther
	case "":
	default:
		return clOther
	}
	return classifyName(name, entityID)
}

func classifyName(name string, entityID int) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "intru"):
		return clIntrusion
	case strings.Contains(n, "redundan") && (strings.Contains(n, "fan") || entityID == 29 || entityID == 30):
		return clFan
	case entityID == 19 || strings.Contains(n, "pwr unit") || strings.Contains(n, "power unit") ||
		(strings.Contains(n, "redundan") && (strings.Contains(n, "ps") || strings.Contains(n, "pwr") || strings.Contains(n, "power"))) ||
		strings.Contains(n, "power supplies"):
		return clPowerUnit
	case entityID == 10 || psuNumber(name) > 0:
		return clPSU
	case entityID == 29 || entityID == 30 || strings.Contains(n, "fan"):
		return clFan
	case strings.Contains(n, "batt"):
		return clBattery
	case strings.Contains(n, "watchdog"):
		return clWatchdog
	case entityID == 3 || strings.Contains(n, "cpu") || strings.Contains(n, "proc"):
		return clCPU
	case entityID == 8 || entityID == 32 || strings.Contains(n, "dimm") || strings.Contains(n, "mem") || strings.Contains(n, "ecc"):
		return clMemory
	case entityID == 4 || entityID == 26 || strings.Contains(n, "drive") || strings.Contains(n, "hdd") || strings.Contains(n, "disk"):
		return clDisk
	case n == "sel" || strings.Contains(n, "bmc") || strings.Contains(n, "idrac") || strings.Contains(n, "ilo"):
		return clBMC
	}
	return clSystem
}

// selTypeClass maps the sensor type ipmitool prints at the start of the
// SEL sensor column (ipmi_generic_sensor_type_vals) to a class.
var selTypes = []struct{ name, class string }{
	{"Management Subsys Health", clBMC},
	{"System ACPI Power State", clSystem},
	{"Event Logging Disabled", clBMC},
	{"Cable / Interconnect", clSystem},
	{"System Boot Initiated", clSystem},
	{"POST Memory Resize", clMemory},
	{"Physical Security", clIntrusion},
	{"Platform Security", clIntrusion},
	{"Critical Interrupt", clSystem},
	{"OS Critical Stop", clSystem},
	{"Drive Slot / Bay", clDisk},
	{"Drive Slot", clDisk},
	{"System Firmwares", clSystem},
	{"Slot / Connector", clSystem},
	{"Entity Presence", clSystem},
	{"Microcontroller", clBMC},
	{"Cooling Device", clFan},
	{"Module / Board", clSystem},
	{"Version Change", clBMC},
	{"Platform Alert", clSystem},
	{"Session Audit", clBMC},
	{"Power Supply", clPSU},
	{"System Event", clSystem},
	{"Add-in Card", clSystem},
	{"Temperature", clTemp},
	{"Monitor ASIC", clSystem},
	{"Power Unit", clPowerUnit},
	{"Boot Error", clSystem},
	{"Terminator", clSystem},
	{"Other FRU", clSystem},
	{"FRU State", clSystem},
	{"Watchdog1", clWatchdog},
	{"Watchdog2", clWatchdog},
	{"Processor", clCPU},
	{"Chip Set", clSystem},
	{"Voltage", clVoltage},
	{"Current", clCurrent},
	{"Battery", clBattery},
	{"OS Boot", clSystem},
	{"Chassis", clSystem},
	{"Memory", clMemory},
	{"Button", clSystem},
	{"Other", clSystem},
	{"Fan", clFan},
	{"LAN", clSystem},
}

// splitSELSensor splits "Power Supply PS2 Status" into type and name.
func splitSELSensor(s string) (typ, name, class string) {
	s = strings.TrimSpace(s)
	for _, t := range selTypes {
		if s == t.name {
			return t.name, "", t.class
		}
		if strings.HasPrefix(s, t.name+" ") {
			name = strings.TrimSpace(s[len(t.name):])
			class = t.class
			// Generic "Other"/"System Event" types: let the name decide.
			if class == clSystem {
				if c := classifyName(name, 0); c != clSystem {
					class = c
				}
			}
			return t.name, name, class
		}
	}
	return "", s, classifyName(s, 0)
}
