package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	// Wintun's signed prebuilt driver DLL, shipped unmodified next to NoMax.exe as its licence asks.
	wintunURL    = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	wintunZipSum = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
	wintunDLLSum = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
	windowsDist  = "dist/windows"
	// The panel serves this file on the files page; backups skip public/.
	serverEXE = "/var/lib/nomax/public/nomax-setup.exe"
)

// cmdWindows cross-compiles the Windows app and its installer into
// dist/nomax-setup.exe. With -upload it also goes to the server, where the
// join page offers it.
func cmdWindows(env *Env, args []string) {
	fs := flag.NewFlagSet("windows", flag.ExitOnError)
	upload := fs.Bool("upload", false, "put the installer on the server for the join page")
	wintunOnly := fs.Bool("wintun", false, "only fetch wintun.dll into dist/windows")
	fs.Parse(args)

	os.MkdirAll(windowsDist, 0o755)
	fetchWintun()
	if *wintunOnly {
		return
	}
	build := strings.TrimSpace(output("git", "rev-list", "--count", "HEAD"))
	ver := marketingVersion()

	step("building NoMax.exe (build %s)", build)
	run("go", "run", "./windows/res", "-version", ver, "-build", build,
		"-syso", "windows/rsrc_windows_amd64.syso", "-ico", filepath.Join(windowsDist, "NoMax.ico"))
	ldflags := "-s -w -buildid= -H windowsgui -X main.version=" + ver + " -X main.build=" + build + " -X main.host=" + env.Must("DOMAIN") +
		" -X github.com/ginzlabs/nomaxvpn/internal/profile.APIPath=" + env.Get("API_PATH") +
		" -X github.com/ginzlabs/nomaxvpn/internal/apiclient.Relays=" + strings.Join(relays(env), ",") +
		" -X github.com/ginzlabs/nomaxvpn/internal/directory.PublicKey=" + env.Get("DIRECTORY_PUBLIC") +
		" -X github.com/ginzlabs/nomaxvpn/internal/directory.Secret=" + env.Get("DIRECTORY_SECRET") +
		" -X github.com/ginzlabs/nomaxvpn/internal/directory.Name=" + env.Get("DIRECTORY_NAME") +
		" -X github.com/ginzlabs/nomaxvpn/internal/directory.GistURL=" + env.Get("DIRECTORY_GIST")
	if err := runErr([]string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}, "go", "build", "-trimpath",
		"-ldflags", ldflags, "-o", filepath.Join(windowsDist, "NoMax.exe"), "./windows"); err != nil {
		fatalf("go build: %v", err)
	}

	step("building the installer")
	src, _ := filepath.Abs(windowsDist)
	out, _ := filepath.Abs("dist/nomax-setup.exe")
	run("makensis", "-V2", "-DVERSION="+ver, "-DBUILD="+build, "-DSRC="+src, "-DOUT="+out, "windows/installer.nsi")
	step("built dist/nomax-setup.exe")
	if !*upload {
		return
	}
	f, err := os.Open("dist/nomax-setup.exe")
	if err != nil {
		fatalf("%v", err)
	}
	defer f.Close()
	dir := filepath.Dir(serverEXE)
	script := "set -e; install -d -o nomax -g nomax -m 0755 " + dir + "; t=$(mktemp " + dir + "/.exe.XXXXXX); cat > \"$t\"; chown nomax:nomax \"$t\"; chmod 0644 \"$t\"; mv \"$t\" " + serverEXE
	if err := ssh(serverHost(env), script, f); err != nil {
		fatalf("upload: %v", err)
	}
	step("uploaded to the files page")
}

// fetchWintun puts wintun.dll and its licence in dist/windows, checking both checksums.
func fetchWintun() {
	dll := filepath.Join(windowsDist, "wintun.dll")
	if b, err := os.ReadFile(dll); err == nil && sha256Hex(b) == wintunDLLSum {
		return
	}
	step("downloading %s", wintunURL)
	resp, err := http.Get(wintunURL)
	if err != nil {
		fatalf("wintun: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fatalf("wintun: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		fatalf("wintun: %v", err)
	}
	if got := sha256Hex(data); got != wintunZipSum {
		fatalf("wintun: the zip's checksum is %s, want %s", got, wintunZipSum)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		fatalf("wintun: %v", err)
	}
	for name, dst := range map[string]string{"wintun/bin/amd64/wintun.dll": dll, "wintun/LICENSE.txt": filepath.Join(windowsDist, "wintun-LICENSE.txt")} {
		f, err := zr.Open(name)
		if err != nil {
			fatalf("wintun: %v", err)
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			fatalf("wintun: %v", err)
		}
		if dst == dll && sha256Hex(b) != wintunDLLSum {
			fatalf("wintun: wintun.dll's checksum doesn't match")
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			fatalf("%v", err)
		}
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
