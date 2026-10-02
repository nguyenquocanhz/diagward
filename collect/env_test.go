package collect

import "testing"

func TestClassifyVirt(t *testing.T) {
	cases := []struct{ vendor, product, want string }{
		{"Dell Inc.", "PowerEdge R740", ""},
		{"HPE", "ProLiant DL380 Gen10", ""},
		{"Supermicro", "SYS-1029P-WTR", ""},
		{"QEMU", "Standard PC (Q35 + ICH9, 2009)", "kvm"},
		{"Red Hat", "RHEL 7.6.0 PC (i440FX + PIIX, 1996)", "kvm"},
		{"oVirt", "oVirt Node", "kvm"},
		{"Red Hat", "KVM", "kvm"},
		{"BHYVE", "BHYVE", "bhyve"},
		{"Hetzner", "vServer", "kvm"},
		{"Microsoft Corporation", "Virtual Machine", "microsoft"},
		{"VMware, Inc.", "VMware Virtual Platform", "vmware"},
		{"Xen", "HVM domU", "xen"},
		{"Amazon EC2", "m5.large", "amazon"},
		{"Red Hat", "OpenStack Compute", "kvm"},
	}
	for _, c := range cases {
		if got := classifyVirt(c.vendor, c.product); got != c.want {
			t.Errorf("classifyVirt(%q, %q) = %q, want %q", c.vendor, c.product, got, c.want)
		}
	}
	bios := []struct{ maker, version, want string }{
		{"American Megatrends Inc.", "3.4", ""},
		{"Dell Inc.", "2.12.2", ""},
		{"SeaBIOS", "rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org", "kvm"},
		{"EFI Development Kit II / OVMF", "0.0.0", "kvm"},
		{"Microsoft Corporation", "VRTUAL - 12001807", "microsoft"},
		{"Phoenix Technologies LTD", "VMW71.00V.18227214.B64.2106252220", "vmware"},
	}
	for _, c := range bios {
		if got := classifyBIOS(c.maker, c.version); got != c.want {
			t.Errorf("classifyBIOS(%q, %q) = %q, want %q", c.maker, c.version, got, c.want)
		}
	}
}
