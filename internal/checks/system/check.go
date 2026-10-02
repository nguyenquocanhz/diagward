// Package system is the "system" domain check. (Stub: replaced by the real implementation.)
package system

import (
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	return model.Result{Domain: "system"}
}

// HostInfo identifies the machine for the report header.
func HostInfo(b *collect.Bundle, env model.Env) model.HostInfo {
	return model.HostInfo{Hostname: b.Get("meta.ident").KV()["hostname"], Virtual: env.Virtual}
}
