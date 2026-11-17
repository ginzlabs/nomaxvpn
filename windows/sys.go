//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	findWindow          = user32.NewProc("FindWindowW")
	showWindow          = user32.NewProc("ShowWindow")
	setWindowPos        = user32.NewProc("SetWindowPos")
	setWindowLongPtr    = user32.NewProc("SetWindowLongPtrW")
	callWindowProc      = user32.NewProc("CallWindowProcW")
	postMessage         = user32.NewProc("PostMessageW")
	systemParametersInf = user32.NewProc("SystemParametersInfoW")
	setForegroundWindow = user32.NewProc("SetForegroundWindow")
	getDpiForSystem     = user32.NewProc("GetDpiForSystem")
	openClipboard       = user32.NewProc("OpenClipboard")
	closeClipboard      = user32.NewProc("CloseClipboard")
	emptyClipboard      = user32.NewProc("EmptyClipboard")
	setClipboardData    = user32.NewProc("SetClipboardData")
	globalAlloc         = kernel32.NewProc("GlobalAlloc")
	globalFree          = kernel32.NewProc("GlobalFree")
	globalLock          = kernel32.NewProc("GlobalLock")
	globalUnlock        = kernel32.NewProc("GlobalUnlock")
	moveMemory          = kernel32.NewProc("RtlMoveMemory")
)

// singleInstance is false when NoMax is already open, after bringing its window forward.
func singleInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\NoMax.App`)
	_, err := windows.CreateMutex(nil, false, name)
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return true
	}
	class, _ := windows.UTF16PtrFromString("webview")
	title, _ := windows.UTF16PtrFromString("NoMax")
	if hwnd, _, _ := findWindow.Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title))); hwnd != 0 {
		showWindow.Call(hwnd, swRestore)
		setForegroundWindow.Call(hwnd)
	}
	return false
}

func localAppData() string {
	if dir, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0); err == nil {
		return dir
	}
	return os.TempDir()
}

// scaled is n logical pixels in the screen's pixels: the manifest makes the app DPI-aware.
func scaled(n uint) uint {
	if getDpiForSystem.Find() != nil {
		return n
	}
	dpi, _, _ := getDpiForSystem.Call()
	if dpi == 0 {
		return n
	}
	return n * uint(dpi) / 96
}

// workArea is the main screen without the taskbar, in pixels; ok is false if Windows won't say.
func workArea() (r windows.Rect, ok bool) {
	const spiGetWorkArea = 0x0030
	got, _, _ := systemParametersInf.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0)
	return r, got != 0 && r.Bottom > r.Top
}

// moveWindow puts the window's top left corner at x, y, keeping its size.
func moveWindow(hwnd uintptr, x, y int32) {
	const swpNoSize, swpNoZOrder, swpNoActivate = 0x0001, 0x0004, 0x0010
	setWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder|swpNoActivate)
}

const (
	wmClose = 0x0010
	// wmQuitNoMax has NoMax disconnect and close without asking. The installer
	// sends it before replacing NoMax.exe (windows/installer.nsi).
	wmQuitNoMax = 0x8000 + 0x4E // WM_APP + 'N'
	swMinimize  = 6
	swRestore   = 9
)

var (
	windowProc uintptr
	quitting   atomic.Bool
)

// guardClose has closing the window ask first when ask says so: ask shows
// the question, and quit closes for real.
func guardClose(hwnd uintptr, ask func() bool) {
	proc := windows.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
		switch msg {
		case wmQuitNoMax:
			quitting.Store(true)
			msg = wmClose
		case wmClose:
			if !quitting.Load() && ask() {
				return 0
			}
		}
		r, _, _ := callWindowProc.Call(windowProc, h, msg, wp, lp)
		return r
	})
	const gwlpWndProc = ^uintptr(3) // -4
	windowProc, _, _ = setWindowLongPtr.Call(hwnd, gwlpWndProc, proc)
}

// quit closes the window without asking.
func quit(hwnd uintptr) {
	quitting.Store(true)
	postMessage.Call(hwnd, wmClose, 0, 0)
}

func fail(msg string) {
	text, _ := windows.UTF16PtrFromString(msg)
	title, _ := windows.UTF16PtrFromString("NoMax")
	windows.MessageBox(0, text, title, windows.MB_OK|windows.MB_ICONERROR)
}

func darkTitleBar(hwnd uintptr) {
	on := int32(1)
	windows.DwmSetWindowAttribute(windows.HWND(hwnd), windows.DWMWA_USE_IMMERSIVE_DARK_MODE, unsafe.Pointer(&on), 4)
}

// seal encrypts for this Windows user (DPAPI), so another account can't read the device's keys.
func seal(b []byte) ([]byte, error) {
	in := blob(b)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(out), nil
}

func unseal(b []byte) ([]byte, error) {
	in := blob(b)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(out), nil
}

func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func take(d windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(d.Data)))
	return append([]byte(nil), unsafe.Slice(d.Data, d.Size)...)
}

func copyText(hwnd uintptr, s string) error {
	if r, _, err := openClipboard.Call(hwnd); r == 0 {
		return fmt.Errorf("the clipboard is busy: %w", err)
	}
	defer closeClipboard.Call()
	emptyClipboard.Call()
	text := utf16.Encode([]rune(s + "\x00"))
	size := uintptr(len(text) * 2)
	const gmemMoveable, cfUnicodeText = 0x0002, 13
	mem, _, err := globalAlloc.Call(gmemMoveable, size)
	if mem == 0 {
		return err
	}
	p, _, err := globalLock.Call(mem)
	if p == 0 {
		globalFree.Call(mem)
		return err
	}
	moveMemory.Call(p, uintptr(unsafe.Pointer(&text[0])), size)
	globalUnlock.Call(mem)
	if r, _, err := setClipboardData.Call(cfUnicodeText, mem); r == 0 {
		globalFree.Call(mem)
		return err
	}
	return nil
}

// reveal opens Explorer with the file selected.
func reveal(path string) error {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return err
	}
	attr := &os.ProcAttr{Sys: &syscall.SysProcAttr{CmdLine: `explorer.exe /select,"` + path + `"`}}
	p, err := os.StartProcess(dir+`\explorer.exe`, nil, attr)
	if err != nil {
		return err
	}
	return p.Release()
}

func windowsVersion() string {
	v := windows.RtlGetVersion()
	name := fmt.Sprintf("Windows %d", v.MajorVersion)
	if v.MajorVersion == 10 && v.BuildNumber >= 22000 {
		name = "Windows 11"
	}
	return fmt.Sprintf("%s (build %d)", name, v.BuildNumber)
}
