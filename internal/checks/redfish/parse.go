package redfish

import (
	"path"
	"strings"

	"github.com/nguyenquocanhz/diagward/model"
)

// Facts is the typed data of this domain.
type Facts struct {
	Service      Service       `json:"service"`
	Systems      []System      `json:"systems,omitempty"`
	Chassis      []ChassisInfo `json:"chassis,omitempty"`
	Managers     []Manager     `json:"managers,omitempty"`
	Temperatures []Temperature `json:"temperatures,omitempty"`
	Fans         []Fan         `json:"fans,omitempty"`
	PSUs         []PSU         `json:"psus,omitempty"`
	Voltages     []Voltage     `json:"voltages,omitempty"`
	Redundancy   []Redundancy  `json:"redundancy,omitempty"`
	Drives       []Drive       `json:"drives,omitempty"`
	Volumes      []Volume      `json:"volumes,omitempty"`
	Controllers  []Controller  `json:"controllers,omitempty"`
	Batteries    []Battery     `json:"batteries,omitempty"`
	DIMMs        []DIMM        `json:"dimms,omitempty"`
	CPUs         []CPU         `json:"cpus,omitempty"`
	NICs         []NIC         `json:"nics,omitempty"`
	Events       []EventGroup  `json:"events,omitempty"`
	PowerWatts   *float64      `json:"powerWatts,omitempty"`
	WindowDays   int           `json:"windowDays"`
}

// Service is the Redfish service root.
type Service struct {
	Vendor         string `json:"vendor,omitempty"`
	Product        string `json:"product,omitempty"`
	RedfishVersion string `json:"redfishVersion,omitempty"`
}

// System is one ComputerSystem.
type System struct {
	ID           string  `json:"id"`
	Manufacturer string  `json:"manufacturer,omitempty"`
	Model        string  `json:"model,omitempty"`
	SerialNumber string  `json:"serialNumber,omitempty"`
	SKU          string  `json:"sku,omitempty"`
	BiosVersion  string  `json:"biosVersion,omitempty"`
	HostName     string  `json:"hostName,omitempty"`
	PowerState   string  `json:"powerState,omitempty"`
	Status       Status  `json:"status"`
	CPUCount     int     `json:"cpuCount,omitempty"`
	CPUModel     string  `json:"cpuModel,omitempty"`
	MemoryGiB    float64 `json:"memoryGiB,omitempty"`
}

// ChassisInfo is one Chassis.
type ChassisInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	PowerState string `json:"powerState,omitempty"`
	Status     Status `json:"status"`
}

// Manager is one BMC.
type Manager struct {
	ID              string `json:"id"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmwareVersion,omitempty"`
	Status          Status `json:"status"`
}

// Temperature is one temperature sensor.
type Temperature struct {
	Name     string         `json:"name"`
	Reading  *float64       `json:"reading,omitempty"`
	Warn     *float64       `json:"warn,omitempty"`  // UpperThresholdNonCritical / UpperCaution
	Crit     *float64       `json:"crit,omitempty"`  // UpperThresholdCritical / UpperCritical
	Fatal    *float64       `json:"fatal,omitempty"` // UpperThresholdFatal / UpperFatal
	Status   Status         `json:"status"`
	Severity model.Severity `json:"severity"`
}

// Fan is one fan.
type Fan struct {
	Name      string         `json:"name"`
	Reading   *float64       `json:"reading,omitempty"`
	Units     string         `json:"units,omitempty"` // RPM or Percent
	LowerCrit *float64       `json:"lowerCrit,omitempty"`
	Model     string         `json:"model,omitempty"`
	Serial    string         `json:"serial,omitempty"`
	Part      string         `json:"partNumber,omitempty"`
	Status    Status         `json:"status"`
	Severity  model.Severity `json:"severity"`
}

// PSU is one power supply.
type PSU struct {
	Name            string         `json:"name"`
	Model           string         `json:"model,omitempty"`
	Manufacturer    string         `json:"manufacturer,omitempty"`
	Serial          string         `json:"serial,omitempty"`
	Part            string         `json:"partNumber,omitempty"`
	Firmware        string         `json:"firmware,omitempty"`
	CapacityW       *float64       `json:"capacityWatts,omitempty"`
	InputV          *float64       `json:"inputVolts,omitempty"`
	OutputW         *float64       `json:"outputWatts,omitempty"`
	LineInputStatus string         `json:"lineInputStatus,omitempty"`
	Status          Status         `json:"status"`
	Severity        model.Severity `json:"severity"`
}

// Voltage is one voltage sensor.
type Voltage struct {
	Name      string   `json:"name"`
	Reading   *float64 `json:"reading,omitempty"`
	LowerCrit *float64 `json:"lowerCrit,omitempty"`
	UpperCrit *float64 `json:"upperCrit,omitempty"`
	LowerWarn *float64 `json:"lowerWarn,omitempty"`
	UpperWarn *float64 `json:"upperWarn,omitempty"`
	Status    Status   `json:"status"`
}

// Redundancy is a fan or power supply redundancy group.
type Redundancy struct {
	Kind   string `json:"kind"` // "fan" or "psu"
	Name   string `json:"name,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Status Status `json:"status"`
}

// Drive is one physical drive.
type Drive struct {
	ID               string         `json:"id"`
	ref              string         // normalised @odata.id, to match RAID members
	Name             string         `json:"name,omitempty"`
	Location         string         `json:"location,omitempty"`
	Model            string         `json:"model,omitempty"`
	Manufacturer     string         `json:"manufacturer,omitempty"`
	Serial           string         `json:"serial,omitempty"`
	Firmware         string         `json:"firmware,omitempty"`
	MediaType        string         `json:"mediaType,omitempty"`
	Protocol         string         `json:"protocol,omitempty"`
	CapacityBytes    uint64         `json:"capacityBytes,omitempty"`
	FailurePredicted *bool          `json:"failurePredicted,omitempty"`
	LifeLeftPercent  *float64       `json:"lifeLeftPercent,omitempty"`
	Status           Status         `json:"status"`
	Severity         model.Severity `json:"severity"`
}

// Volume is one RAID volume (logical drive).
type Volume struct {
	ID            string         `json:"id"`
	members       []string       // normalised @odata.id of member drives
	uid           string         // durable identifier, to drop HPE SmartStorage duplicates
	Name          string         `json:"name,omitempty"`
	RAID          string         `json:"raid,omitempty"`
	CapacityBytes uint64         `json:"capacityBytes,omitempty"`
	RaidStatus    string         `json:"raidStatus,omitempty"` // vendor OEM state (Dell RaidStatus)
	Rebuilding    bool           `json:"rebuilding,omitempty"`
	RebuildPct    *float64       `json:"rebuildPercent,omitempty"`
	Status        Status         `json:"status"`
	Severity      model.Severity `json:"severity"`
}

// Controller is one storage controller.
type Controller struct {
	Name     string `json:"name"`
	Model    string `json:"model,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	Status   Status `json:"status"`
	Cache    Status `json:"cache"`
}

// Battery is an HPE Smart Storage Battery (it backs the Smart Array write
// cache); iLO reports it only in its Oem block.
type Battery struct {
	Name      string         `json:"name"`
	Model     string         `json:"model,omitempty"`
	Spare     string         `json:"sparePart,omitempty"`
	Serial    string         `json:"serial,omitempty"`
	Firmware  string         `json:"firmware,omitempty"`
	Condition string         `json:"condition,omitempty"` // iLO 4: Ok, Failed, ...
	Status    Status         `json:"status"`
	Severity  model.Severity `json:"severity"`
}

// DIMM is one memory module.
type DIMM struct {
	Slot         string         `json:"slot"`
	Manufacturer string         `json:"manufacturer,omitempty"`
	PartNumber   string         `json:"partNumber,omitempty"`
	Serial       string         `json:"serial,omitempty"`
	Type         string         `json:"type,omitempty"`
	CapacityMiB  float64        `json:"capacityMiB,omitempty"`
	SpeedMHz     float64        `json:"speedMHz,omitempty"`
	Status       Status         `json:"status"`
	Severity     model.Severity `json:"severity"`
}

// CPU is one processor socket.
type CPU struct {
	Socket string `json:"socket"`
	Model  string `json:"model,omitempty"`
	Cores  int    `json:"cores,omitempty"`
	Status Status `json:"status"`
}

// NIC is one host Ethernet interface.
type NIC struct {
	Name       string  `json:"name"`
	MAC        string  `json:"mac,omitempty"`
	LinkStatus string  `json:"linkStatus,omitempty"`
	SpeedMbps  float64 `json:"speedMbps,omitempty"`
	Status     Status  `json:"status"`
}

// logService is a log to read entries from.
type logService struct {
	id, name, entries string
}

// walker reads the stored resources by following links from the service
// root, exactly like the collector did.
type walker struct {
	s     *store
	f     *Facts
	areas map[string]*area
	logs  []logService
	// rollups are the overall health values the BMC reports.
	rollups []rollup
}

type rollup struct {
	what   string
	health string
}

func (w *walker) area(id string) *area { return w.areas[id] }

func (w *walker) walk(root map[string]any) {
	w.f.Service = Service{Vendor: str(root, "Vendor"), Product: str(root, "Product"), RedfishVersion: str(root, "RedfishVersion")}
	if w.f.Service.Vendor == "" {
		for k := range obj(root, "Oem") {
			if w.f.Service.Vendor == "" || k < w.f.Service.Vendor {
				w.f.Service.Vendor = k
			}
		}
	}
	sysA := w.area("system")
	if coll := w.s.read(sysA, link(root, "Systems")); coll != nil {
		for _, sys := range w.s.members(sysA, coll) {
			w.system(sys)
		}
	}
	thA, pwA := w.area("thermal"), w.area("power")
	if ref := link(root, "Chassis"); ref != "" {
		coll, oc, why := w.s.get(ref)
		thA.note(oc, why)
		pwA.note(oc, why)
		if coll != nil {
			for _, ch := range w.s.members(nil, coll) {
				w.chassis(ch)
			}
		}
	}
	if coll := w.s.read(nil, link(root, "Managers")); coll != nil {
		for _, m := range w.s.members(nil, coll) {
			st := statusOf(m)
			w.f.Managers = append(w.f.Managers, Manager{ID: first(str(m, "Id"), path.Base(str(m, "@odata.id"))), Model: str(m, "Model"), FirmwareVersion: str(m, "FirmwareVersion"), Status: st})
			w.logServices(link(m, "LogServices"))
		}
	}
}

func (w *walker) system(s map[string]any) {
	sys := System{
		ID:           first(str(s, "Id"), path.Base(str(s, "@odata.id"))),
		Manufacturer: str(s, "Manufacturer"),
		Model:        str(s, "Model"),
		SerialNumber: str(s, "SerialNumber"),
		SKU:          str(s, "SKU"),
		BiosVersion:  str(s, "BiosVersion"),
		HostName:     str(s, "HostName"),
		PowerState:   str(s, "PowerState"),
		Status:       statusOf(s),
		CPUModel:     str(s, "ProcessorSummary", "Model"),
	}
	if n := num(s, "ProcessorSummary", "Count"); n != nil && *n > 0 && *n < 1024 {
		sys.CPUCount = int(*n)
	}
	if g := num(s, "MemorySummary", "TotalSystemMemoryGiB"); g != nil && *g > 0 {
		sys.MemoryGiB = *g
	}
	w.f.Systems = append(w.f.Systems, sys)
	w.rollups = append(w.rollups, rollup{"system " + sys.ID, first(sys.Status.HealthRollup, sys.Status.Health)})

	sysA := w.area("system")
	// iLO 4 links Processors only under "links", Memory only under
	// Oem.Hp.links (its "Processors" and "Memory" are summary objects).
	if coll := w.s.read(sysA, first(link(s, "Processors"), link(s, "links", "Processors"))); coll != nil {
		for _, p := range w.s.members(sysA, coll) {
			st := statusOf(p)
			if t := strings.ToLower(str(p, "ProcessorType")); t != "" && t != "cpu" {
				continue // FPGA, GPU, accelerators: not CPUs
			}
			c := CPU{Socket: first(str(p, "Socket"), str(p, "Location", "PartLocation", "ServiceLabel"), str(p, "Id")), Model: str(p, "Model"), Status: st}
			if n := num(p, "TotalCores"); n != nil && *n > 0 && *n < 4096 {
				c.Cores = int(*n)
			}
			w.f.CPUs = append(w.f.CPUs, c)
		}
	}
	if coll := w.s.read(sysA, first(link(s, "EthernetInterfaces"), link(s, "links", "EthernetInterfaces"))); coll != nil {
		for _, e := range w.s.members(sysA, coll) {
			n := NIC{Name: first(str(e, "Name"), str(e, "Id")), MAC: first(str(e, "MACAddress"), str(e, "PermanentMACAddress")), LinkStatus: str(e, "LinkStatus"), Status: statusOf(e)}
			if v := num(e, "SpeedMbps"); v != nil {
				n.SpeedMbps = *v
			}
			w.f.NICs = append(w.f.NICs, n)
		}
	}

	memA := w.area("memory")
	if coll := w.s.read(memA, first(link(s, "Memory"), link(s, "Oem", "Hp", "links", "Memory"))); coll != nil {
		for _, m := range w.s.members(memA, coll) {
			w.dimm(m)
		}
	}

	stA := w.area("storage")
	nDrives := len(w.f.Drives)
	if coll := w.s.read(stA, link(s, "Storage")); coll != nil {
		for _, st := range w.s.members(stA, coll) {
			w.storage(st)
		}
	}
	if ss := w.s.read(stA, first(link(s, "Oem", "Hpe", "Links", "SmartStorage"), link(s, "Oem", "Hp", "links", "SmartStorage"))); ss != nil {
		w.smartStorage(ss)
	}
	simple := w.s.read(stA, link(s, "SimpleStorage"))
	if simple != nil && len(w.f.Drives) == nDrives {
		// Only when Storage gave no drives: SimpleStorage lists the same
		// disks with less detail.
		for _, ss := range w.s.members(stA, simple) {
			ctl := statusOf(ss)
			if !ctl.Absent() && (ctl.Health != "" || ctl.State != "") {
				w.f.Controllers = append(w.f.Controllers, Controller{Name: first(str(ss, "Name"), str(ss, "Id")), Status: ctl})
			}
			for _, d := range objs(ss, "Devices") {
				dr := Drive{ID: str(d, "Name"), Name: str(d, "Name"), Model: str(d, "Model"), Manufacturer: str(d, "Manufacturer"), Status: statusOf(d)}
				if c := num(d, "CapacityBytes"); c != nil && *c > 0 {
					dr.CapacityBytes = uint64(*c)
				}
				w.f.Drives = append(w.f.Drives, dr)
			}
		}
	} else if simple != nil {
		_ = w.s.members(stA, simple) // still account for the reads
	}
	w.logServices(link(s, "LogServices"))
	w.batteries(objs(hpOem(s), "Battery")) // iLO 4
}

// batteries reads HPE Smart Storage Batteries: iLO 4 lists them in the
// system's Oem.Hp.Battery (Present, Condition), iLO 5/6 in the chassis'
// Oem.Hpe.SmartStorageBattery (Status). Both carry model, spare part number
// and serial.
func (w *walker) batteries(list []map[string]any) {
	for _, b := range list {
		if strings.EqualFold(str(b, "Present"), "No") {
			continue
		}
		bat := Battery{
			Name:      first(str(b, "ProductName"), "Smart Storage Battery "+str(b, "Index")),
			Model:     str(b, "Model"),
			Spare:     first(str(b, "Spare"), str(b, "SparePartNumber")),
			Serial:    str(b, "SerialNumber"),
			Firmware:  str(b, "FirmwareVersion"),
			Condition: str(b, "Condition"),
			Status:    statusOf(b),
		}
		if bat.Status.Absent() {
			continue
		}
		dup := false
		for _, o := range w.f.Batteries {
			dup = dup || (bat.Serial != "" && o.Serial == bat.Serial)
		}
		if !dup {
			w.f.Batteries = append(w.f.Batteries, bat)
		}
	}
}

func (w *walker) dimm(m map[string]any) {
	d := DIMM{
		Slot:         first(str(m, "DeviceLocator"), str(m, "Location", "PartLocation", "ServiceLabel"), str(m, "SocketLocator"), str(m, "Name"), str(m, "Id")),
		Manufacturer: str(m, "Manufacturer"),
		PartNumber:   str(m, "PartNumber"),
		Serial:       str(m, "SerialNumber"),
		Type:         first(str(m, "MemoryDeviceType"), str(m, "MemoryType"), str(m, "DIMMType")),
		Status:       statusOf(m),
	}
	if v := num(m, "CapacityMiB"); v != nil && *v > 0 {
		d.CapacityMiB = *v
	} else if v := num(m, "SizeMB"); v != nil && *v > 0 { // iLO 4 HpMemory schema
		d.CapacityMiB = *v
	}
	if v := num(m, "OperatingSpeedMhz"); v != nil && *v > 0 {
		d.SpeedMHz = *v
	}
	// HPE lists every slot; empty ones are Absent or have no capacity.
	// DIMMStatus (Oem.Hpe on iLO 5, top level on the HpMemory schema of
	// iLO 4, which has no Status at all) also tells a failed module.
	hs := strings.ToLower(first(str(hpOem(m), "DIMMStatus"), str(m, "DIMMStatus")))
	if hs == "notpresent" {
		d.Status.State = "Absent"
	}
	if d.Status.Health == "" {
		d.Status.Health = dimmStatusHealth(hs)
	}
	if d.Status.Absent() || (d.CapacityMiB == 0 && d.Status.Health == "" && d.Serial == "") {
		return
	}
	w.f.DIMMs = append(w.f.DIMMs, d)
}

// dimmStatusHealth maps HPE's DIMMStatus (HpeMemory / HpMemory schemas) to
// a Redfish health when the BMC gives none: a module mapped out after
// errors is Critical; degraded, unsupported, mismatched, misconfigured or
// expected-but-missing modules are Warning; the rest say nothing.
func dimmStatusHealth(s string) string {
	switch s {
	case "goodinuse", "goodpartiallyinuse", "presentspare", "presentunused", "addedbutunused", "upgradedbutunused":
		return "OK"
	case "mapouterror":
		return "Critical"
	case "degraded", "doesnotmatch", "notsupported", "configurationerror", "expectedbutmissing", "mapoutconfiguration":
		return "Warning"
	}
	return ""
}

func (w *walker) storage(st map[string]any) {
	stA := w.area("storage")
	for _, c := range objs(st, "StorageControllers") {
		w.addController(controllerOf(c))
	}
	if coll := w.s.read(stA, link(st, "Controllers")); coll != nil && len(objs(st, "StorageControllers")) == 0 {
		for _, c := range w.s.members(stA, coll) {
			w.addController(controllerOf(c))
		}
	}
	for _, ref := range links(st, "Drives") {
		if d := w.s.read(stA, ref); d != nil {
			w.addDrive(driveOf(d))
		}
	}
	if coll := w.s.read(stA, link(st, "Volumes")); coll != nil {
		for _, v := range w.s.members(stA, coll) {
			// Dell lists every non-RAID drive as a "RawDevice" volume: it
			// is a drive, already judged as one, not a RAID volume.
			if strings.EqualFold(str(v, "VolumeType"), "RawDevice") {
				continue
			}
			w.addVolume(volumeOf(v))
		}
	}
}

// addDrive adds a drive unless the same drive (same serial number) was
// already read: HPE iLO 5/6 show Smart Array drives both in the standard
// Storage tree and in the older Oem SmartStorage tree.
func (w *walker) addDrive(d Drive) {
	if d.Serial != "" {
		for _, o := range w.f.Drives {
			if strings.EqualFold(o.Serial, d.Serial) {
				return
			}
		}
	}
	w.f.Drives = append(w.f.Drives, d)
}

func (w *walker) addVolume(v Volume) {
	if v.uid != "" {
		for _, o := range w.f.Volumes {
			if o.uid == v.uid {
				return
			}
		}
	}
	w.f.Volumes = append(w.f.Volumes, v)
}

func (w *walker) addController(c Controller) {
	if c.Serial != "" {
		for _, o := range w.f.Controllers {
			if strings.EqualFold(o.Serial, c.Serial) {
				return
			}
		}
	}
	w.f.Controllers = append(w.f.Controllers, c)
}

// normID reduces a durable name ("600508B1-001C-2F66-07D3-27AE65E786C6",
// "600508B1001C2F6607D327AE65E786C6") to lower-case hex digits.
func normID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	if b.Len() < 8 {
		return ""
	}
	return b.String()
}

// smartStorage reads HPE's Oem SmartStorage tree (iLO 4/5).
func (w *walker) smartStorage(ss map[string]any) {
	stA := w.area("storage")
	coll := w.s.read(stA, first(link(ss, "Links", "ArrayControllers"), link(ss, "links", "ArrayControllers")))
	for _, ac := range w.s.members(stA, coll) {
		c := controllerOf(ac)
		if cm := obj(ac, "CacheModuleStatus"); cm != nil {
			c.Cache = Status{Health: str(cm, "Health")}
		}
		w.addController(c)
		for _, d := range w.s.members(stA, w.s.read(stA, first(link(ac, "Links", "PhysicalDrives"), link(ac, "links", "PhysicalDrives")))) {
			w.addDrive(driveOf(d))
		}
		for _, v := range w.s.members(stA, w.s.read(stA, first(link(ac, "Links", "LogicalDrives"), link(ac, "links", "LogicalDrives")))) {
			w.addVolume(volumeOf(v))
		}
	}
}

func controllerOf(c map[string]any) Controller {
	return Controller{
		Name:     first(genericName(str(c, "Name")), str(c, "Model"), str(c, "MemberId"), str(c, "Id")),
		Model:    str(c, "Model"),
		Serial:   str(c, "SerialNumber"),
		Firmware: first(str(c, "FirmwareVersion"), str(c, "FirmwareVersion", "Current", "VersionString")),
		Status:   statusOf(c),
		Cache:    statusOf(obj(c, "CacheSummary")),
	}
}

func driveOf(d map[string]any) Drive {
	dr := Drive{
		ref:              normKey(str(d, "@odata.id")),
		ID:               first(str(d, "Id"), path.Base(str(d, "@odata.id"))),
		Name:             genericName(str(d, "Name")),
		Model:            str(d, "Model"),
		Manufacturer:     str(d, "Manufacturer"),
		Serial:           str(d, "SerialNumber"),
		Firmware:         first(str(d, "Revision"), str(d, "FirmwareVersion"), str(d, "FirmwareVersion", "Current", "VersionString")),
		MediaType:        str(d, "MediaType"),
		Protocol:         first(str(d, "Protocol"), str(d, "InterfaceType")),
		FailurePredicted: boolp(d, "FailurePredicted"),
		LifeLeftPercent:  num(d, "PredictedMediaLifeLeftPercent"),
		Status:           statusOf(d),
	}
	dr.Location = first(str(d, "PhysicalLocation", "PartLocation", "ServiceLabel"), str(d, "PhysicalLocation", "Info"), str(d, "Location"))
	if dr.Location == "" {
		for _, l := range objs(d, "Location") {
			if dr.Location = str(l, "Info"); dr.Location != "" {
				break
			}
		}
	}
	switch {
	case num(d, "CapacityBytes") != nil && *num(d, "CapacityBytes") > 0:
		dr.CapacityBytes = uint64(*num(d, "CapacityBytes"))
	case num(d, "CapacityMiB") != nil && *num(d, "CapacityMiB") > 0: // HPE SmartStorage
		dr.CapacityBytes = uint64(*num(d, "CapacityMiB") * (1 << 20))
	case num(d, "CapacityGB") != nil && *num(d, "CapacityGB") > 0:
		dr.CapacityBytes = uint64(*num(d, "CapacityGB") * 1e9)
	}
	if dr.LifeLeftPercent == nil {
		// HPE SmartStorage reports wear used, not life left.
		if u := num(d, "SSDEnduranceUtilizationPercentage"); u != nil && *u >= 0 && *u <= 100 {
			left := 100 - *u
			dr.LifeLeftPercent = &left
		}
	}
	if dr.LifeLeftPercent != nil && (*dr.LifeLeftPercent < 0 || *dr.LifeLeftPercent > 100) {
		dr.LifeLeftPercent = nil
	}
	return dr
}

func volumeOf(v map[string]any) Volume {
	vol := Volume{
		ID:     first(str(v, "Id"), path.Base(str(v, "@odata.id"))),
		Name:   first(str(v, "LogicalDriveName"), genericName(str(v, "Name"))),
		RAID:   first(str(v, "RAIDType"), str(v, "VolumeType")),
		Status: statusOf(v),
	}
	for _, l := range links(v, "Links", "Drives") {
		vol.members = append(vol.members, normKey(l))
	}
	vol.uid = normID(str(v, "VolumeUniqueIdentifier")) // HPE SmartStorage
	for _, id := range objs(v, "Identifiers") {
		if vol.uid == "" {
			vol.uid = normID(str(id, "DurableName"))
		}
	}
	if r := str(v, "Raid"); vol.RAID == "" && r != "" { // HPE SmartStorage: "Raid": "1"
		vol.RAID = "RAID" + r
	}
	if c := num(v, "CapacityBytes"); c != nil && *c > 0 {
		vol.CapacityBytes = uint64(*c)
	} else if c := num(v, "CapacityMiB"); c != nil && *c > 0 {
		vol.CapacityBytes = uint64(*c * (1 << 20))
	}
	for _, op := range objs(v, "Operations") {
		if strings.Contains(strings.ToLower(str(op, "OperationName")+str(op, "Operation")), "rebuild") {
			vol.Rebuilding = true
			vol.RebuildPct = num(op, "PercentageComplete")
		}
	}
	// Vendor RAID state (Dell: Oem.Dell.DellVolume.RaidStatus).
	for _, vendor := range obj(v, "Oem") {
		vm, _ := vendor.(map[string]any)
		if s := str(vm, "RaidStatus"); s != "" {
			vol.RaidStatus = s
		}
		for _, sub := range vm {
			if sm, ok := sub.(map[string]any); ok {
				if s := str(sm, "RaidStatus"); s != "" {
					vol.RaidStatus = s
				}
			}
		}
	}
	return vol
}

func (w *walker) chassis(ch map[string]any) {
	info := ChassisInfo{ID: first(str(ch, "Id"), path.Base(str(ch, "@odata.id"))), Name: str(ch, "Name"), PowerState: str(ch, "PowerState"), Status: statusOf(ch)}
	w.f.Chassis = append(w.f.Chassis, info)
	w.rollups = append(w.rollups, rollup{"chassis " + info.ID, first(info.Status.HealthRollup, info.Status.Health)})

	thA, pwA := w.area("thermal"), w.area("power")
	// Mirror the collector: classic Thermal first; the newer
	// ThermalSubsystem + Sensors only when Thermal is absent or failed.
	thermal, oc := w.readTry(thA, link(ch, "Thermal"))
	if thermal != nil {
		w.thermal(thermal)
	} else if link(ch, "Thermal") == "" || oc != outMissing {
		w.thermalSubsystem(ch)
	}
	power, oc := w.readTry(pwA, link(ch, "Power"))
	if power != nil {
		w.power(power)
	} else if link(ch, "Power") == "" || oc != outMissing {
		w.powerSubsystem(ch)
	}
	w.logServices(link(ch, "LogServices"))
	w.batteries(objs(hpOem(ch), "SmartStorageBattery")) // iLO 5/6
}

func (w *walker) readTry(a *area, ref string) (map[string]any, outcome) {
	if ref == "" {
		return nil, outMissing
	}
	o, oc, why := w.s.get(ref)
	if oc != outNotFound || o != nil {
		a.note(oc, why)
	}
	return o, oc
}

func (w *walker) thermal(t map[string]any) {
	for _, s := range objs(t, "Temperatures") {
		w.f.Temperatures = append(w.f.Temperatures, Temperature{
			Name:    first(str(s, "Name"), str(s, "MemberId")),
			Reading: num(s, "ReadingCelsius"),
			Warn:    num(s, "UpperThresholdNonCritical"),
			Crit:    num(s, "UpperThresholdCritical"),
			Fatal:   num(s, "UpperThresholdFatal"),
			Status:  statusOf(s),
		})
	}
	for _, f := range objs(t, "Fans") {
		fan := Fan{
			Name:      first(str(f, "Name"), str(f, "FanName"), str(f, "MemberId")),
			Reading:   num(f, "Reading"),
			Units:     str(f, "ReadingUnits"),
			LowerCrit: minPtr(num(f, "LowerThresholdCritical"), num(f, "LowerThresholdFatal")),
			Model:     str(f, "Model"),
			Serial:    str(f, "SerialNumber"),
			Part:      str(f, "PartNumber"),
			Status:    statusOf(f),
		}
		if fan.Reading == nil {
			fan.Reading = num(f, "ReadingRPM") // Thermal v1_0
			if fan.Reading != nil {
				fan.Units = "RPM"
			}
		}
		if fan.Reading == nil {
			// HPE iLO 4: "CurrentReading": 17, "Units": "Percent".
			fan.Reading = num(f, "CurrentReading")
			if u := str(f, "Units"); fan.Reading != nil && fan.Units == "" && u != "" {
				fan.Units = u
			}
		}
		if fan.Units == "" {
			fan.Units = "RPM"
		}
		w.f.Fans = append(w.f.Fans, fan)
	}
	for _, r := range objs(t, "Redundancy") {
		w.f.Redundancy = append(w.f.Redundancy, Redundancy{Kind: "fan", Name: str(r, "Name"), Mode: str(r, "Mode"), Status: statusOf(r)})
	}
}

func firstNum(ps ...*float64) *float64 {
	for _, p := range ps {
		if p != nil {
			return p
		}
	}
	return nil
}

// minPtr returns the larger of two lower limits that are set (the one hit
// first when a fan slows down).
func minPtr(a, b *float64) *float64 {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case *b > *a:
		return b
	}
	return a
}

func (w *walker) thermalSubsystem(ch map[string]any) {
	thA := w.area("thermal")
	if ts := w.s.read(thA, link(ch, "ThermalSubsystem")); ts != nil {
		for _, f := range w.s.members(thA, w.s.read(thA, link(ts, "Fans"))) {
			fan := Fan{
				Name:   first(str(f, "Location", "PartLocation", "ServiceLabel"), str(f, "Name"), str(f, "Id")),
				Model:  str(f, "Model"),
				Serial: str(f, "SerialNumber"),
				Part:   str(f, "PartNumber"),
				Status: statusOf(f),
			}
			if rpm := num(f, "SpeedPercent", "SpeedRPM"); rpm != nil {
				fan.Reading, fan.Units = rpm, "RPM"
			} else if pct := num(f, "SpeedPercent", "Reading"); pct != nil {
				fan.Reading, fan.Units = pct, "Percent"
			}
			w.f.Fans = append(w.f.Fans, fan)
		}
		for _, r := range objs(ts, "FanRedundancy") {
			w.f.Redundancy = append(w.f.Redundancy, Redundancy{Kind: "fan", Mode: str(r, "RedundancyType"), Status: statusOf(r)})
		}
		nTemps := len(w.f.Temperatures)
		w.sensors(ch)
		if len(w.f.Temperatures) == nTemps {
			if tm := w.s.read(thA, link(ts, "ThermalMetrics")); tm != nil {
				for _, r := range objs(tm, "TemperatureReadingsCelsius") {
					w.f.Temperatures = append(w.f.Temperatures, Temperature{Name: first(str(r, "DeviceName"), path.Base(str(r, "DataSourceUri"))), Reading: num(r, "Reading")})
				}
			}
		}
		return
	}
	w.sensors(ch)
}

// sensors reads the Sensor resources (newer schema): temperatures with
// thresholds, voltages, and fans when ThermalSubsystem had none.
func (w *walker) sensors(ch map[string]any) {
	thA := w.area("thermal")
	coll := w.s.read(thA, link(ch, "Sensors"))
	if coll == nil {
		return
	}
	hadFans := len(w.f.Fans) > 0
	for _, s := range w.s.members(thA, coll) {
		typ := strings.ToLower(str(s, "ReadingType"))
		units := str(s, "ReadingUnits")
		name := first(str(s, "Name"), str(s, "Id"))
		th := func(k string) *float64 { return num(s, "Thresholds", k, "Reading") }
		switch {
		case typ == "temperature" || units == "Cel":
			w.f.Temperatures = append(w.f.Temperatures, Temperature{Name: name, Reading: num(s, "Reading"), Warn: th("UpperCaution"), Crit: th("UpperCritical"), Fatal: th("UpperFatal"), Status: statusOf(s)})
		case typ == "voltage" || units == "V":
			w.f.Voltages = append(w.f.Voltages, Voltage{Name: name, Reading: num(s, "Reading"), LowerCrit: th("LowerCritical"), UpperCrit: th("UpperCritical"), LowerWarn: th("LowerCaution"), UpperWarn: th("UpperCaution"), Status: statusOf(s)})
		case !hadFans && (typ == "rotational" || units == "RPM"):
			w.f.Fans = append(w.f.Fans, Fan{Name: name, Reading: num(s, "Reading"), Units: "RPM", LowerCrit: minPtr(th("LowerCritical"), th("LowerFatal")), Status: statusOf(s)})
		}
	}
}

func (w *walker) power(p map[string]any) {
	for _, s := range objs(p, "PowerSupplies") {
		w.f.PSUs = append(w.f.PSUs, PSU{
			Name:         psuName(s),
			Model:        str(s, "Model"),
			Manufacturer: str(s, "Manufacturer"),
			Serial:       str(s, "SerialNumber"),
			Part:         str(s, "PartNumber"),
			Firmware:     str(s, "FirmwareVersion"),
			CapacityW:    num(s, "PowerCapacityWatts"),
			InputV:       num(s, "LineInputVoltage"),
			OutputW:      num(s, "LastPowerOutputWatts"),
			Status:       statusOf(s),
		})
	}
	for _, v := range objs(p, "Voltages") {
		w.f.Voltages = append(w.f.Voltages, Voltage{
			Name:      first(str(v, "Name"), str(v, "MemberId")),
			Reading:   num(v, "ReadingVolts"),
			LowerCrit: num(v, "LowerThresholdCritical"),
			UpperCrit: num(v, "UpperThresholdCritical"),
			LowerWarn: num(v, "LowerThresholdNonCritical"),
			UpperWarn: num(v, "UpperThresholdNonCritical"),
			Status:    statusOf(v),
		})
	}
	for _, c := range objs(p, "PowerControl") {
		if v := num(c, "PowerConsumedWatts"); v != nil && *v > 0 && w.f.PowerWatts == nil {
			w.f.PowerWatts = v
		}
	}
	for _, r := range objs(p, "Redundancy") {
		w.f.Redundancy = append(w.f.Redundancy, Redundancy{Kind: "psu", Name: str(r, "Name"), Mode: str(r, "Mode"), Status: statusOf(r)})
	}
}

func (w *walker) powerSubsystem(ch map[string]any) {
	pwA := w.area("power")
	if ps := w.s.read(pwA, link(ch, "PowerSubsystem")); ps != nil {
		for _, s := range w.s.members(pwA, w.s.read(pwA, link(ps, "PowerSupplies"))) {
			psu := PSU{
				Name:            first(str(s, "Location", "PartLocation", "ServiceLabel"), str(s, "Name"), str(s, "Id")),
				Model:           str(s, "Model"),
				Manufacturer:    str(s, "Manufacturer"),
				Serial:          str(s, "SerialNumber"),
				Part:            str(s, "PartNumber"),
				Firmware:        str(s, "FirmwareVersion"),
				CapacityW:       num(s, "PowerCapacityWatts"),
				LineInputStatus: str(s, "LineInputStatus"),
				Status:          statusOf(s),
			}
			if m := w.s.read(pwA, link(s, "Metrics")); m != nil {
				psu.InputV = num(m, "InputVoltage", "Reading")
				psu.OutputW = num(m, "OutputPowerWatts", "Reading")
			}
			w.f.PSUs = append(w.f.PSUs, psu)
		}
		for _, r := range objs(ps, "PowerSupplyRedundancy") {
			w.f.Redundancy = append(w.f.Redundancy, Redundancy{Kind: "psu", Mode: str(r, "RedundancyType"), Status: statusOf(r)})
		}
	}
	if em := w.s.read(nil, link(ch, "EnvironmentMetrics")); em != nil && w.f.PowerWatts == nil {
		if v := num(em, "PowerWatts", "Reading"); v != nil && *v > 0 {
			w.f.PowerWatts = v
		}
	}
}

// Log services that hold no hardware events; must match the collector
// (package bmc, skipLog). Matched against the service Id; skipNames also
// against its Name, because Supermicro calls both of its logs "Log1" and only
// the Name tells the maintenance (audit) log from the health event log.
var (
	skipLogServices = []string{"dump", "crash", "postcode", "hostlogger", "journal", "audit", "debug", "diag", "fdr", "telemetry", "maintenance"}
	skipLogNames    = []string{"audit", "maintenance", "security log"}
)

// SkipLogService reports whether a LogService (by its Id and Name) holds no
// hardware events: dumps, POST codes, the BMC's own journal, audit,
// maintenance and security logs (HPE iLO "SL").
func SkipLogService(id, name string) bool {
	low := strings.ToLower(strings.TrimSpace(id))
	if low == "sl" {
		return true
	}
	for _, s := range skipLogServices {
		if strings.Contains(low, s) {
			return true
		}
	}
	n := strings.ToLower(name)
	for _, s := range skipLogNames {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func (w *walker) logServices(ref string) {
	lgA := w.area("logs")
	coll := w.s.read(lgA, ref)
	for _, ls := range w.s.members(lgA, coll) {
		id := first(str(ls, "Id"), path.Base(str(ls, "@odata.id")))
		if SkipLogService(id, str(ls, "Name")) || link(ls, "Entries") == "" {
			continue
		}
		w.logs = append(w.logs, logService{id: id, name: first(str(ls, "Name"), id), entries: link(ls, "Entries")})
	}
}

// psuName names a power supply in the classic Power resource. HPE names
// every one "HpeServerPowerSupply"; its bay number tells them apart.
func psuName(s map[string]any) string {
	name := first(str(s, "Name"), str(s, "MemberId"))
	if bay := str(hpOem(s), "BayNumber"); bay != "" && (name == "" || strings.HasPrefix(name, "HpeServer") || strings.HasPrefix(name, "HpServer")) {
		return "Power Supply Bay " + bay
	}
	return name
}

// genericName drops HPE's schema-type names ("HpeSmartStorageDiskDrive"),
// which name every instance the same.
func genericName(n string) string {
	if strings.HasPrefix(n, "HpeSmartStorage") || strings.HasPrefix(n, "HpeServer") || strings.HasPrefix(n, "HpSmartStorage") || strings.HasPrefix(n, "HpServer") {
		return ""
	}
	return n
}
