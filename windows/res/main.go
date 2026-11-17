// Command res makes the Windows app's resources: the icon, drawn from the
// mark's geometry (apple/App/AppIcon.icon), and a manifest that asks for
// administrator rights, which creating the Wintun adapter needs. It writes
// windows/rsrc_windows_amd64.syso, which go build links in, and NoMax.ico
// for the installer.
//
//	go run ./windows/res -version 1.4 -build 120
package main

import (
	"flag"
	"image"
	"image/color"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func main() {
	ver := flag.String("version", "dev", "version people see, such as git describe's")
	build := flag.Int("build", 0, "build number")
	syso := flag.String("syso", "windows/rsrc_windows_amd64.syso", "resource object to write")
	ico := flag.String("ico", "dist/windows/NoMax.ico", "icon file to write")
	flag.Parse()

	var imgs []image.Image
	for _, n := range []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256} {
		imgs = append(imgs, draw(n))
	}
	icon, err := winres.NewIconFromImages(imgs)
	if err != nil {
		log.Fatal(err)
	}
	rs := winres.ResourceSet{}
	rs.SetIcon(winres.ID(1), icon)
	rs.SetManifest(winres.AppManifest{
		Description:         "NoMax",
		Compatibility:       winres.Win10AndAbove,
		ExecutionLevel:      winres.RequireAdministrator,
		DPIAwareness:        winres.DPIPerMonitorV2,
		UseCommonControlsV6: true,
	})
	vi := version.Info{}
	numeric := "1.0.0." + strconv.Itoa(*build)
	vi.SetFileVersion(numeric)
	vi.SetProductVersion(numeric)
	for k, v := range map[string]string{
		version.ProductName:      "NoMax",
		version.FileDescription:  "NoMax",
		version.OriginalFilename: "NoMax.exe",
		version.LegalCopyright:   "GPLv3",
		version.ProductVersion:   *ver + " (" + strconv.Itoa(*build) + ")",
	} {
		vi.Set(0, k, v)
	}
	rs.SetVersionInfo(vi)

	write(*syso, func(w io.Writer) error { return rs.WriteObject(w, winres.ArchAMD64) })
	write(*ico, icon.SaveICO)
}

func write(path string, fill func(io.Writer) error) {
	os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := fill(f); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

// draw is the icon at n pixels: the silver mark on a black rounded square,
// laid out as on the 1024-point iPhone icon.
func draw(n int) image.Image {
	const ss = 8 // samples per pixel side
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	scale := 1024 / float64(n)
	for py := range n {
		for px := range n {
			var bg, mark int
			for sy := range ss {
				for sx := range ss {
					x := (float64(px) + (float64(sx)+.5)/ss) * scale
					y := (float64(py) + (float64(sy)+.5)/ss) * scale
					if inSquare(x, y) {
						bg++
						if inMark(x, y) {
							mark++
						}
					}
				}
			}
			if bg == 0 {
				continue
			}
			// The mark's gradient runs top to bottom, #F4F5F7 to #A2A7AF.
			y := (float64(py) + .5) * scale
			t := math.Max(0, math.Min(1, (y-250.88)/522.24))
			m := float64(mark) / float64(bg)
			lerp := func(a, b float64) uint8 { return uint8(math.Round(m * (a + (b-a)*t))) }
			img.SetNRGBA(px, py, color.NRGBA{
				R: lerp(0xF4, 0xA2), G: lerp(0xF5, 0xA7), B: lerp(0xF7, 0xAF),
				A: uint8(math.Round(255 * float64(bg) / ss / ss)),
			})
		}
	}
	return img
}

// inSquare is the background: the brand's Windows squircle, a superellipse of
// exponent 5 filling the icon.
func inSquare(x, y float64) bool {
	return math.Pow(math.Abs(x-512)/512, 5)+math.Pow(math.Abs(y-512)/512, 5) <= 1
}

// inMark is the arch with its legs and the lock's bar, in the iPhone icon's coordinates.
func inMark(x, y float64) bool {
	const (
		w      = 83.97 // the stroke
		cap    = w / 2
		left   = 281.6
		right  = 742.4 - w
		spring = 481.28 // where the arch meets the legs
		bottom = 773.12 - cap
	)
	bar := func(left, top, bottom float64) bool {
		cx := left + cap
		if x < left || x > left+w {
			return false
		}
		return (y >= top && y <= bottom) || math.Hypot(x-cx, y-top) <= cap || math.Hypot(x-cx, y-bottom) <= cap
	}
	if d := math.Hypot(x-512, y-spring); y <= spring && d >= 230.4-w && d <= 230.4 {
		return true
	}
	// The lock's bar sits below the right leg, 30.72 apart.
	return bar(left, spring, bottom) || bar(right, spring, 559.31-cap) || bar(right, 590.03+cap, bottom)
}
