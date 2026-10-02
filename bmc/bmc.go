// Package bmc reads a server's management controller out of band. (Stub: replaced by the real implementation.)
package bmc

import (
	"context"
	"errors"
	"time"

	"github.com/nguyenquocanhz/diagward/collect"
)

// Options select the BMC and how to reach it.
type Options struct {
	Host      string // address or URL of the BMC (iDRAC, iLO, XClarity, Supermicro, OpenBMC)
	Port      int    // 0 = default (443 for Redfish, 623 for IPMI)
	User      string
	Password  string
	Insecure  bool          // skip TLS certificate verification (self-signed BMC certificates)
	Protocol  string        // "auto" (Redfish, then IPMI), "redfish" or "ipmi"
	Timeout   time.Duration // whole collection; 0 = 2 minutes
	SinceDays int           // event log window; 0 = 30
}

// Collect reads the BMC into a bundle with OS = collect.OSBMC.
func Collect(ctx context.Context, o Options) (*collect.Bundle, error) {
	return nil, errors.New("not implemented")
}
