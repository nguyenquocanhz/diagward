// Package network is the "network" domain check. (Stub: replaced by the real implementation.)
package network

import (
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	return model.Result{Domain: "network"}
}
