package sensors

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
)

// kelvin10 converts tenths of a Kelvin (the unit of
// MSAcpi_ThermalZoneTemperature) to °C. 0 means "not reported".
func kelvin10(v *float64) *float64 {
	if v == nil || *v <= 0 {
		return nil
	}
	return fptr(*v/10 - 273.15)
}

// parseWinThermal reads root\wmi MSAcpi_ThermalZoneTemperature: ACPI
// thermal zones (_TMP, _CRT, _PSV), all in tenths of Kelvin.
func parseWinThermal(sec *collect.Section) []*reading {
	var zs []struct {
		InstanceName       string   `json:"InstanceName"`
		CurrentTemperature *float64 `json:"CurrentTemperature"`
		CriticalTripPoint  *float64 `json:"CriticalTripPoint"`
		PassiveTripPoint   *float64 `json:"PassiveTripPoint"`
	}
	if collect.DecodeJSON(sec.Text(), &zs) != nil {
		return nil
	}
	var out []*reading
	for i, z := range zs {
		name := strings.TrimSpace(z.InstanceName)
		if name == "" {
			name = fmt.Sprintf("ThermalZone%d", i)
		}
		name = strings.TrimPrefix(name, `ACPI\ThermalZone\`)
		out = append(out, &reading{
			Source: srcACPI, Chip: "ACPI", Driver: "acpitz", Kind: kTemp, Label: name,
			Input: kelvin10(z.CurrentTemperature), Crit: kelvin10(z.CriticalTripPoint), Passive: kelvin10(z.PassiveTripPoint),
		})
	}
	return out
}

// parseWinProbe reads Win32_TemperatureProbe (SMBIOS type 28). Readings are
// in tenths of °C and are almost never filled in by the firmware.
func parseWinProbe(sec *collect.Section) []*reading {
	var ps []struct {
		Name           string   `json:"Name"`
		DeviceID       string   `json:"DeviceID"`
		Status         string   `json:"Status"`
		CurrentReading *float64 `json:"CurrentReading"`
	}
	if collect.DecodeJSON(sec.Text(), &ps) != nil {
		return nil
	}
	var out []*reading
	for _, p := range ps {
		if p.CurrentReading == nil {
			continue
		}
		label := firstNonEmpty(p.Name, p.DeviceID, "probe")
		out = append(out, &reading{Source: srcSMBIOS, Chip: "SMBIOS", Kind: kTemp, Label: label,
			Input: fptr(*p.CurrentReading / 10), Status: p.Status})
	}
	return out
}

// parseWinFan reads Win32_Fan (SMBIOS cooling devices). No live speed, only
// the static status the firmware reported; listed for inventory only.
func parseWinFan(sec *collect.Section) []*reading {
	var fs []struct {
		Name         string   `json:"Name"`
		DeviceID     string   `json:"DeviceID"`
		Status       string   `json:"Status"`
		DesiredSpeed *float64 `json:"DesiredSpeed"`
	}
	if collect.DecodeJSON(sec.Text(), &fs) != nil {
		return nil
	}
	var out []*reading
	for _, f := range fs {
		out = append(out, &reading{Source: srcSMBIOS, Chip: "SMBIOS", Kind: kFan,
			Label: firstNonEmpty(f.Name, f.DeviceID, "fan"), Status: strings.TrimSpace(f.Status)})
	}
	return out
}

// parseHM reads the LibreHardwareMonitor / OpenHardwareMonitor WMI class
// Sensor. Their Min/Max are the lowest/highest values seen since the tool
// started, NOT thresholds, so they are not used for alarms.
func parseHM(sec *collect.Section, src string) []*reading {
	var ss []struct {
		SensorType string   `json:"SensorType"`
		Name       string   `json:"Name"`
		Value      *float64 `json:"Value"`
		Parent     string   `json:"Parent"`
		Identifier string   `json:"Identifier"`
	}
	if collect.DecodeJSON(sec.Text(), &ss) != nil {
		return nil
	}
	var out []*reading
	for _, s := range ss {
		var kind string
		switch strings.ToLower(s.SensorType) {
		case "temperature":
			kind = kTemp
		case "fan":
			kind = kFan
		case "voltage":
			kind = kIn
		case "power":
			kind = kPower
		case "current":
			kind = kCurr
		default:
			continue
		}
		n := strings.ToLower(s.Name)
		// "Core #1 Distance to TjMax" is a temperature-typed margin, not a
		// temperature; averages duplicate the per-core values.
		if kind == kTemp && (strings.Contains(n, "distance to tjmax") || strings.Contains(n, "average")) {
			continue
		}
		parent := s.Parent
		if parent == "" {
			parent = s.Identifier
		}
		drv := ""
		pl := strings.ToLower(parent)
		if strings.Contains(pl, "cpu") {
			drv = "cpu"
		}
		r := &reading{Source: src, Chip: parent, Driver: drv, Kind: kind, Label: s.Name, Index: s.Identifier}
		if s.Value != nil {
			r.Input = fptr(*s.Value)
		}
		out = append(out, r)
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}
