SHELL := /bin/bash
export PATH := $(CURDIR)/bin:$(PATH)
OPS := go run ./cmd/ops
ANDROID_HOME ?= /opt/homebrew/share/android-commandlinetools
JAVA_HOME ?= /opt/homebrew/opt/openjdk@21
export ANDROID_HOME JAVA_HOME
# The device API's secret path, the relays and the directory, built into the
# apps' Go code. The shell reads them when the command runs, so make doesn't echo them.
CFG = $$(sed -n 's/^$(1)=//p' $${NOMAX_ENV_FILE:-_cert/nomax.env} 2>/dev/null | tr -d ' ')
API_FLAG = -X github.com/ginzlabs/nomaxvpn/internal/profile.APIPath=$(call CFG,API_PATH) \
	-X github.com/ginzlabs/nomaxvpn/internal/apiclient.Relays=$(call CFG,RELAYS) \
	-X github.com/ginzlabs/nomaxvpn/internal/directory.PublicKey=$(call CFG,DIRECTORY_PUBLIC) \
	-X github.com/ginzlabs/nomaxvpn/internal/directory.Secret=$(call CFG,DIRECTORY_SECRET) \
	-X github.com/ginzlabs/nomaxvpn/internal/directory.Name=$(call CFG,DIRECTORY_NAME) \
	-X github.com/ginzlabs/nomaxvpn/internal/directory.GistURL=$(call CFG,DIRECTORY_GIST)

.PHONY: test init up down state-save deploy ssh check probe relay publish admin-code reports core ios ios-test ios-setup ios-signing ios-ci-cert ios-device testflight testflight-mac beta-review mac-dev gh-secrets android-core android android-release windows windows-preview

test:            ## Go tests (includes a loopback Reality/Hysteria2/AmneziaWG tunnel)
	go vet ./... && go test ./...

init:            ## Fill generated secrets in _cert/nomax.env, make the SSH key
	$(OPS) init

up:              ## Create the VPS + DNS (OpenTofu), then deploy
	$(OPS) up

down:            ## Destroy the VPS and its DNS records
	$(OPS) down

state-save:      ## Copy the server's people, devices and keys to _cert/state.tgz; it keeps running
	$(OPS) state-save

deploy:          ## Build nomax for linux and roll it out over SSH
	$(OPS) deploy

ssh:
	$(OPS) ssh

check:           ## Server health: services, ports, certificate
	$(OPS) check

probe:           ## Enrol a throwaway device and push traffic through every protocol
	$(OPS) probe

relay:           ## Set up the relay at RELAY=ip (or every one in RELAYS) and redeploy
	$(OPS) relay

publish:         ## Publish the server's name, addresses and relays to the apps' directory (DNS TXT, gist)
	$(OPS) publish

admin-code:      ## Rotate the admin code (new random one unless ADMIN_CODE=... is given)
	$(OPS) admin-code

reports:         ## What the apps sent with Send, new since the last look (REPORTS_ARGS="-all -since 48h -person alice")
	$(OPS) reports $(REPORTS_ARGS)

core:            ## gomobile -> apple/Frameworks/NomaxCore.xcframework (tunnels) and NomaxCheck.xcframework (apps)
	GOBIN=$(CURDIR)/bin go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
	gomobile bind -target=ios,iossimulator,macos -iosversion=26.0 -trimpath -ldflags="-s -w -buildid= $(API_FLAG)" \
		-o apple/Frameworks/NomaxCore.xcframework ./core
	gomobile bind -target=ios,iossimulator,macos -iosversion=26.0 -trimpath -ldflags="-s -w -buildid= $(API_FLAG)" \
		-o apple/Frameworks/NomaxCheck.xcframework ./check

ios: core        ## Generate the Xcode project and build for the simulator
	cd apple && xcodegen generate --quiet && xcodebuild -project NoMax.xcodeproj -scheme NoMax \
		-destination 'generic/platform=iOS Simulator' -derivedDataPath build/dd CODE_SIGNING_ALLOWED=NO build -quiet

ios-test:        ## UI test on a simulator: join with the App Review PIN against the live server, then leave
	cd apple && xcodegen generate --quiet && TEST_RUNNER_NOMAX_PIN=$$(grep ^REVIEW_CODE= ../_cert/nomax.env | cut -d= -f2) \
		xcodebuild test -project NoMax.xcodeproj -scheme NoMax -destination 'platform=iOS Simulator,name=iPhone 17' \
		-derivedDataPath build/sim CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual -quiet

ios-setup:       ## Bundle IDs + capabilities + TestFlight group in App Store Connect
	$(OPS) ios-setup

ios-signing:     ## Distribution profiles for app and tunnel, installed locally
	$(OPS) ios-signing

ios-ci-cert:     ## Dedicated Apple Distribution cert + p12 for the CI TestFlight workflow
	$(OPS) ios-ci-cert

ios-device:      ## Build a development copy and install it on the connected iPhone
	$(OPS) ios-device

testflight: core ## Archive and upload to TestFlight (TESTFLIGHT_ARGS=-review also submits it)
	$(OPS) testflight $(TESTFLIGHT_ARGS)

testflight-mac: core ## The same for the Mac app
	$(OPS) testflight -mac $(TESTFLIGHT_ARGS)

beta-review:     ## After testing: the newest iOS and Mac builds go to the testers' group and Apple's beta review
	$(OPS) beta-review
	$(OPS) beta-review -mac

mac-dev:         ## Build a development copy of the Mac app and open it
	$(OPS) mac-dev

android-core:    ## gomobile -> android/app/libs/nomaxcore.aar
	GOBIN=$(CURDIR)/bin go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
	mkdir -p android/app/libs
	gomobile bind -target=android/arm64 -androidapi 29 -trimpath -ldflags="-s -w -buildid= -checklinkname=0 $(API_FLAG)" \
		-o android/app/libs/nomaxcore.aar ./core

android: android-core ## Debug APK (android/app/build/outputs/apk/debug)
	cd android && ./gradlew --quiet assembleDebug

android-release: android-core ## Signed APK; ANDROID_ARGS=-upload puts it on the server for the join page
	$(OPS) android $(ANDROID_ARGS)

windows:         ## Windows app and installer in dist/nomax-setup.exe; WINDOWS_ARGS=-upload puts it on the server
	$(OPS) windows $(WINDOWS_ARGS)

windows-preview: ## The Windows app's screens in a browser, with a pretend engine (PIN 123456)
	go run ./windows/preview

gh-secrets:      ## Push CI secrets from _cert/ to GitHub
	$(OPS) gh-secrets
