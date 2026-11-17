package desktop

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// Page is the window's content: one page with its styles and script inline.
//
//go:embed ui/index.html
var Page string

// Call runs one of the page's requests: method, with arg as JSON.
func (a *App) Call(method string, arg json.RawMessage) (any, error) {
	str := func() (string, error) {
		var s string
		if len(arg) > 0 {
			if err := json.Unmarshal(arg, &s); err != nil {
				return "", fmt.Errorf("%s: %w", method, err)
			}
		}
		return s, nil
	}
	switch method {
	case "state":
		return a.State(), nil
	case "join":
		pin, err := str()
		if err != nil {
			return nil, err
		}
		go a.Join(pin)
	case "connect":
		a.Connect(false)
	case "test":
		a.Connect(true)
	case "disconnect":
		go a.Disconnect()
	case "choose":
		id, err := str()
		if err != nil {
			return nil, err
		}
		go a.Choose(id)
	case "chooseRoute":
		id, err := str()
		if err != nil {
			return nil, err
		}
		go a.ChooseRoute(id)
	case "closeRun":
		a.CloseRun()
	case "leave":
		go a.Leave()
	case "checkIP":
		a.CheckIP()
	case "dismissError":
		a.mu.Lock()
		a.err = ""
		a.mu.Unlock()
	case "logs":
		return a.Logs(), nil
	case "logText":
		return a.LogText(), nil
	case "clearLog":
		a.ClearLog()
	case "send":
		a.Send()
	case "minimize":
		if a.platform.Minimize != nil {
			a.platform.Minimize()
		}
	case "close":
		if a.platform.Close != nil {
			a.platform.Close()
		}
	case "checkStart":
		a.CheckStart()
	case "checkState":
		return a.CheckState(), nil
	case "checkText":
		return a.CheckText(), nil
	case "checkCancel":
		a.CheckCancel()
	case "copy":
		s, err := str()
		if err != nil {
			return nil, err
		}
		return nil, a.Copy(s)
	case "save":
		var in struct{ Name, Text string }
		if err := json.Unmarshal(arg, &in); err != nil {
			return nil, err
		}
		return a.Save(in.Name, in.Text)
	default:
		return nil, fmt.Errorf("unknown call %q", method)
	}
	return nil, nil
}
