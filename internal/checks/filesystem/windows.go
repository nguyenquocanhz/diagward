package filesystem

import (
	"fmt"
	"strings"

	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/internal/hint"
	"github.com/nguyenquocanhz/diagward/internal/units"
	"github.com/nguyenquocanhz/diagward/model"
)

type winVolume struct {
	DriveLetter       string
	FileSystemLabel   string
	FileSystem        string
	DriveType         any
	HealthStatus      any
	OperationalStatus any
	Size              uint64
	SizeRemaining     uint64
	Path              string
	// From Win32_Volume (matched on the volume GUID path): the mount
	// folder of a volume without a drive letter ("C:\ClusterStorage\Volume1\"),
	// and whether it is the system (EFI / System Reserved) or boot volume.
	MountPath    string
	SystemVolume bool
	BootVolume   bool
}

// systemLabels are the labels Windows setup and OEM tools give to recovery,
// EFI and System Reserved partitions. They are nearly full by design.
var systemLabels = map[string]bool{
	"system reserved": true, "recovery": true, "windows re tools": true, "winretools": true,
	"recovery image": true, "efi": true, "esp": true, "system": true, "restore": true,
	"dellutility": true, "hp_recovery": true, "lenovo_recovery": true, "dell restore": true,
}

// volumeMount names a volume: its drive letter ("C:"), else its mount
// folder without the trailing backslash, else "".
func volumeMount(v winVolume) (mnt, letter string) {
	letter = strings.ToUpper(strings.TrimSpace(strings.TrimSuffix(v.DriveLetter, ":")))
	if len(letter) == 1 {
		return letter + ":", letter
	}
	letter = ""
	mp := strings.TrimSpace(v.MountPath)
	if mp == "" || strings.HasPrefix(mp, `\\?\`) {
		return "", ""
	}
	if t := strings.TrimRight(mp, `\`); len(t) > 2 {
		return t, ""
	}
	return "", ""
}

// enumText normalises a CIM enum that may arrive as a string ("Fixed") or a
// number (3), using names for the known numbers.
func enumText(v any, names map[int]string) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if s, ok := names[int(x)]; ok {
			return s
		}
		return fmt.Sprint(int(x))
	case []any:
		var out []string
		for _, e := range x {
			if s := enumText(e, names); s != "" {
				out = append(out, s)
			}
		}
		return strings.Join(out, ", ")
	}
	return ""
}

// MSFT_Volume enums (Storage Management API): DriveType 3 = Fixed;
// HealthStatus 0 = Healthy, 1 = Warning, 2 = Unhealthy, 5 = Unknown.
var driveTypes = map[int]string{0: "Unknown", 1: "Invalid", 2: "Removable", 3: "Fixed", 4: "Remote", 5: "CD-ROM", 6: "RAM disk"}
var healthNames = map[int]string{0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}
var opNames = map[int]string{
	0: "Unknown", 2: "OK", 3: "Degraded", 5: "Predictive Failure", 6: "Error", 10: "Stopped", 13: "Lost Communication",
	0xD00D: "Scan Needed", 0xD00E: "Spot Fix Needed", 0xD00F: "Full Repair Needed",
}

func checkWindows(b *collect.Bundle, env model.Env, res *model.Result) {
	sec := b.Get("filesystem.win_volume")
	var vols []winVolume
	err := collect.DecodeJSON(sec.Text(), &vols)
	space := model.Coverage{ID: "filesystem.space", Component: model.CompFilesystem, Name: model.T("Free space", "Dung lượng trống")}
	health := model.Coverage{ID: "filesystem.health", Component: model.CompFilesystem, Name: model.T("Volume health and dirty bit (chkdsk)", "Tình trạng volume và cờ dirty (chkdsk)")}
	switch {
	case sec.Missing != "":
		space.State, space.Reason = model.CovSkipped, model.T("Get-Volume is not available (Windows Server 2012 or later is needed).", "Không có lệnh Get-Volume (cần Windows Server 2012 trở lên).")
		health.State, health.Reason = space.State, space.Reason
		res.Coverage = append(res.Coverage, space, health)
		return
	case err != nil || (sec.RC != 0 && len(vols) == 0):
		space.State = model.CovFailed
		space.Reason = model.Tf("Get-Volume failed: %s", "Get-Volume bị lỗi: %s", firstLine(firstNonEmpty(sec.Err, "unreadable output")))
		health.State, health.Reason = space.State, space.Reason
		res.Coverage = append(res.Coverage, space, health)
		return
	}
	space.State, health.State = model.CovRan, model.CovRan

	dirty := map[string]bool{}
	ds := b.Get("filesystem.win_dirty")
	switch {
	case ds == nil:
	case ds.Skipped == "not-admin":
		health.State, health.Reason, health.Fix = model.CovPartial,
			model.T("The dirty bit (chkdsk pending) can only be read as Administrator.", "Chỉ đọc được cờ dirty (cần chạy chkdsk) khi có quyền Administrator."), hint.RunAsRoot(env)
	default:
		var dv []struct {
			DriveLetter string
			Name        string
			DeviceID    string
			DirtyBitSet *bool
		}
		if collect.DecodeJSON(ds.Text(), &dv) == nil {
			for _, d := range dv {
				if d.DirtyBitSet != nil && *d.DirtyBitSet {
					if l := strings.ToUpper(strings.TrimSuffix(d.DriveLetter, ":")); l != "" {
						dirty[l] = true
					}
					if d.DeviceID != "" {
						dirty[strings.ToLower(d.DeviceID)] = true
					}
				}
			}
		}
	}
	res.Coverage = append(res.Coverage, space, health)

	var fss []FS
	status := map[string]model.Severity{}
	healthProblems, checked := 0, 0
	for _, v := range vols {
		dt := enumText(v.DriveType, driveTypes)
		if !strings.EqualFold(dt, "Fixed") || v.Size == 0 {
			continue // removable and optical media are not server storage
		}
		mnt, letter := volumeMount(v)
		label := strings.TrimSpace(v.FileSystemLabel)
		sysPart := v.SystemVolume || systemLabels[strings.ToLower(label)]
		if mnt == "" && sysPart {
			continue // EFI / recovery partition without a letter: nothing to check
		}
		hs := enumText(v.HealthStatus, healthNames)
		ops := enumText(v.OperationalStatus, opNames)
		isDirty := dirty[letter] && letter != "" || v.Path != "" && dirty[strings.ToLower(v.Path)]
		target := mnt
		if target == "" {
			// A data volume with neither a letter nor a mount folder: it gets
			// health checks, but its space is nobody's working space.
			target = firstNonEmpty(label, v.Path)
		}
		used := v.Size - min(v.SizeRemaining, v.Size)
		if mnt != "" {
			fs := FS{Mount: mnt, Device: firstNonEmpty(label, v.Path), Type: v.FileSystem,
				SizeBytes: v.Size, UsedBytes: used, AvailBytes: min(v.SizeRemaining, v.Size),
				State: hs, Dirty: isDirty, SystemPartition: sysPart,
				Boot: v.BootVolume || (letter == "C" && !anyBoot(vols))}
			fs.UsePct = pctOf(used, fs.AvailBytes)
			fss = append(fss, fs)
		}
		checked++

		// chkdsk takes a drive letter, a mount folder or a volume GUID path;
		// Repair-Volume takes -DriveLetter or -Path (the GUID path).
		chk := firstNonEmpty(mnt, v.Path, target)
		repair := "Repair-Volume -DriveLetter " + letter + " -OfflineScanAndFix"
		if letter == "" {
			repair = "Repair-Volume -Path '" + v.Path + "' -OfflineScanAndFix"
		}
		ev := []string{fmt.Sprintf("%s %q %s: health=%s operational=%s, size %s, free %s, %s", target, label, v.FileSystem, orDash(hs), orDash(ops), units.SI(v.Size), units.SI(min(v.SizeRemaining, v.Size)), v.Path)}
		switch strings.ToLower(hs) {
		case "unhealthy", "warning":
			sev := model.Warn
			if strings.EqualFold(hs, "Unhealthy") {
				// "Full Repair Needed": NTFS found corruption that needs an
				// offline chkdsk; data is at risk.
				sev = model.Crit
			}
			healthProblems++
			status[target] = max(status[target], sev)
			res.Findings = append(res.Findings, model.Finding{
				ID: "filesystem.volume_unhealthy", Component: model.CompFilesystem, Severity: sev, Target: target,
				Title: model.Tf("Volume %s reports health %q (%s)", "Volume %s báo tình trạng %q (%s)", target, hs, orDash(ops)),
				Detail: model.T("Windows found filesystem corruption on this volume (NTFS/ReFS self-check). Unrepaired corruption can lose files and often comes from a failing disk or controller.",
					"Windows phát hiện hệ thống tệp trên volume này bị hỏng (NTFS/ReFS tự kiểm tra). Lỗi chưa được sửa có thể làm mất file và thường do ổ đĩa hoặc controller sắp hỏng."),
				Action: model.Tf("Back up the volume. Check the Disks and RAID sections and the System event log (Ntfs, disk, storahci events). Then run chkdsk %s /scan, and schedule chkdsk %s /f (or %s) in a maintenance window.",
					"Sao lưu volume. Xem mục Ổ cứng, RAID và System event log (sự kiện Ntfs, disk, storahci). Sau đó chạy chkdsk %s /scan và lên lịch chkdsk %s /f (hoặc %s) trong giờ bảo trì.", chk, chk, repair),
				Evidence: ev,
			})
		}
		if isDirty {
			healthProblems++
			status[target] = max(status[target], model.Warn)
			res.Findings = append(res.Findings, model.Finding{
				ID: "filesystem.dirty", Component: model.CompFilesystem, Severity: model.Warn, Target: target,
				Title: model.Tf("Volume %s is marked dirty: chkdsk is needed", "Volume %s bị đánh dấu dirty: cần chạy chkdsk", target),
				Detail: model.T("NTFS sets the dirty bit when it detects an inconsistency or the volume was not cleanly dismounted. Windows will run chkdsk at the next boot, which can take a long time on large volumes.",
					"NTFS bật cờ dirty khi phát hiện bất thường hoặc volume không được tháo an toàn. Windows sẽ chạy chkdsk ở lần khởi động tới, có thể rất lâu với volume lớn."),
				Action: model.Tf("Back up, check the Disks section, then run chkdsk %s /scan now and plan chkdsk %s /f in a maintenance window (check the state with: fsutil dirty query %s).",
					"Sao lưu, xem mục Ổ cứng, rồi chạy chkdsk %s /scan ngay và lên lịch chkdsk %s /f trong giờ bảo trì (kiểm tra lại bằng: fsutil dirty query %s).", chk, chk, chk),
				Evidence: []string{fmt.Sprintf("Win32_Volume %s DirtyBitSet=True", target)},
			})
		}
	}
	spaceFindings(fss, nil, status, res, env)
	if healthProblems == 0 && checked > 0 {
		res.Findings = append(res.Findings, model.Finding{
			ID: "filesystem.health_ok", Component: model.CompFilesystem, Severity: model.OK,
			Title: model.Tf("%d volume(s) report healthy", "%d volume báo tình trạng tốt", checked),
		})
	}
	finishTable(fss, nil, status, res)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// anyBoot reports whether the collector marked a boot volume (older
// collectors did not send BootVolume; then C: is assumed).
func anyBoot(vols []winVolume) bool {
	for _, v := range vols {
		if v.BootVolume {
			return true
		}
	}
	return false
}
