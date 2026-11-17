package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	androidKeystore = "_cert/android.p12"
	releaseAPK      = "android/app/build/outputs/apk/release/app-release.apk"
	// The panel serves this file on the files page; backups skip public/.
	serverAPK = "/var/lib/nomax/public/nomax.apk"
)

// cmdAndroid builds the signed release APK into dist/. With -upload it also
// goes to the server, where the join page offers it. Run `make android-core` first.
func cmdAndroid(env *Env, args []string) {
	fs := flag.NewFlagSet("android", flag.ExitOnError)
	upload := fs.Bool("upload", false, "put the APK on the server for the join page")
	fs.Parse(args)

	ensureAndroidKeystore(env)
	ks, _ := filepath.Abs(androidKeystore)
	build := strings.TrimSpace(output("git", "rev-list", "--count", "HEAD"))
	step("building the release APK (build %s)", build)
	c := exec.Command("./gradlew", "--quiet", "assembleRelease")
	c.Dir = "android"
	c.Env = append(os.Environ(),
		"ANDROID_KEYSTORE="+ks,
		"ANDROID_KEYSTORE_PASSWORD="+env.Must("ANDROID_KEYSTORE_PASSWORD"),
		"VERSION_CODE="+build,
		"VERSION_NAME="+marketingVersion(),
		"NOMAX_HOST="+env.Must("DOMAIN"),
	)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		fatalf("gradle: %v", err)
	}
	os.MkdirAll("dist", 0o755)
	copyFile(releaseAPK, "dist/nomax.apk")
	step("built dist/nomax.apk")
	if !*upload {
		return
	}
	f, err := os.Open(releaseAPK)
	if err != nil {
		fatalf("%v", err)
	}
	defer f.Close()
	dir := filepath.Dir(serverAPK)
	script := "set -e; install -d -o nomax -g nomax -m 0755 " + dir + "; t=$(mktemp " + dir + "/.apk.XXXXXX); cat > \"$t\"; chown nomax:nomax \"$t\"; chmod 0644 \"$t\"; mv \"$t\" " + serverAPK
	if err := ssh(serverHost(env), script, f); err != nil {
		fatalf("upload: %v", err)
	}
	step("uploaded to the files page")
}

// ensureAndroidKeystore makes the release signing key once. Android only
// accepts updates signed with the same key, so it lives in _cert/ with the rest.
func ensureAndroidKeystore(env *Env) {
	if _, err := os.Stat(androidKeystore); err == nil {
		return
	}
	if os.Getenv("CI") != "" {
		fatalf("%s is missing; run make gh-secrets after the first local make android-release", androidKeystore)
	}
	step("creating the Android signing key in %s", androidKeystore)
	pass := randomString("abcdefghijkmnpqrstuvwxyz23456789", 32)
	keytool := "keytool"
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		keytool = filepath.Join(jh, "bin", "keytool")
	}
	if err := runErr([]string{"KS_PASS=" + pass}, keytool, "-genkeypair", "-keystore", androidKeystore, "-storetype", "PKCS12",
		"-alias", "nomax", "-keyalg", "RSA", "-keysize", "4096", "-validity", "10000", "-dname", "CN=NoMax",
		"-storepass:env", "KS_PASS", "-keypass:env", "KS_PASS"); err != nil {
		fatalf("keytool: %v", err)
	}
	env.Set("ANDROID_KEYSTORE_PASSWORD", pass)
	if err := env.Save(); err != nil {
		fatalf("%v", err)
	}
}
