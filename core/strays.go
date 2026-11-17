package nomaxcore

import (
	"sync"

	"github.com/ginzlabs/nomaxvpn/internal/xray"
)

// Every Xray instance the core starts is kept here until it's closed, so Start
// and Stop can close one a teardown missed. On Windows such an instance keeps
// the adapter's routes and its DNS leak filters, which leaves the PC unable to
// look names up after disconnecting.
var (
	runningMu sync.Mutex
	running   = map[*xray.Instance]bool{}
)

func startXray(cfg []byte) (*xray.Instance, error) {
	inst, err := xray.Start(cfg)
	if err != nil {
		return nil, err
	}
	runningMu.Lock()
	running[inst] = true
	runningMu.Unlock()
	return inst, nil
}

func closeXray(inst *xray.Instance) {
	runningMu.Lock()
	delete(running, inst)
	runningMu.Unlock()
	inst.Close()
}

// closeStrays closes the instances still running besides xr, and says how many.
func closeStrays() int {
	runningMu.Lock()
	var strays []*xray.Instance
	for inst := range running {
		if inst != xr {
			strays = append(strays, inst)
		}
	}
	runningMu.Unlock()
	for _, inst := range strays {
		closeXray(inst)
	}
	return len(strays)
}
