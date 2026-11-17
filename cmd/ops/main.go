// Command ops automates NoMax: provisioning, deploys, admin code rotation,
// end-to-end probes, App Store Connect setup and TestFlight uploads.
// Run it from the repo root (the Makefile does).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

var commands = map[string]func(*Env, []string){
	"init":        cmdInit,
	"up":          cmdUp,
	"down":        cmdDown,
	"state-save":  cmdStateSave,
	"deploy":      cmdDeploy,
	"relay":       cmdRelay,
	"publish":     cmdPublish,
	"ssh":         cmdSSH,
	"check":       cmdCheck,
	"probe":       cmdProbe,
	"admin-code":  cmdAdminCode,
	"reports":     cmdReports,
	"ios-setup":   cmdIOSSetup,
	"ios-signing": cmdIOSSigning,
	"ios-ci-cert": cmdIOSCICert,
	"ios-device":  cmdIOSDevice,
	"mac-dev":     cmdMacDev,
	"testflight":  cmdTestFlight,
	"beta-review": cmdBetaReview,
	"gh-secrets":  cmdGHSecrets,
	"android":     cmdAndroid,
	"windows":     cmdWindows,
}

func main() {
	if len(os.Args) < 2 || commands[os.Args[1]] == nil {
		names := make([]string, 0, len(commands))
		for n := range commands {
			names = append(names, n)
		}
		sort.Strings(names)
		fatalf("usage: ops <%s>", strings.Join(names, "|"))
	}
	env, err := loadEnv()
	if err != nil {
		fatalf("%v", err)
	}
	commands[os.Args[1]](env, os.Args[2:])
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ops: "+format+"\n", a...)
	os.Exit(1)
}

func step(format string, a ...any) {
	fmt.Printf("==> "+format+"\n", a...)
}

// run executes a command with inherited stdio, exiting on failure.
func run(name string, args ...string) {
	if err := runErr(nil, name, args...); err != nil {
		fatalf("%s: %v", name, err)
	}
}

func runErr(extraEnv []string, name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(os.Environ(), extraEnv...)
	return c.Run()
}

func output(name string, args ...string) string {
	c := exec.Command(name, args...)
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}
