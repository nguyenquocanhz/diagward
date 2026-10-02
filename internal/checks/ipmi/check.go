// Package ipmi is the "ipmi" domain check. (Stub: replaced by the real implementation.)
package ipmi

import (
	"github.com/nguyenquocanhz/diagward/collect"
	"github.com/nguyenquocanhz/diagward/model"
)

// Check analyzes the bundle for this domain.
func Check(b *collect.Bundle, env model.Env) model.Result {
	return model.Result{Domain: "ipmi"}
}
