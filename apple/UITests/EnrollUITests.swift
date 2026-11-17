import XCTest

/// Joins the real server with the App Review PIN, then removes the device.
/// Run with: TEST_RUNNER_NOMAX_PIN=123456 xcodebuild test ...
final class EnrollUITests: XCTestCase {
    func testEnrollAndLeave() throws {
        let pin = ProcessInfo.processInfo.environment["NOMAX_PIN"] ?? ""
        try XCTSkipIf(pin.isEmpty, "set TEST_RUNNER_NOMAX_PIN")
        let app = XCUIApplication()
        app.launch()

        let field = app.textFields["pin"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        attach(app, "join")

        app.buttons["Check connection"].tap()
        let again = app.buttons["Check again"]
        XCTAssertTrue(again.waitForExistence(timeout: 10))
        attach(app, "check-running")
        expectation(for: NSPredicate(format: "isEnabled == true"), evaluatedWith: again)
        waitForExpectations(timeout: 60)
        attach(app, "check")
        app.buttons["Done"].tap()

        field.tap()
        field.typeText(pin)
        app.buttons["Join"].tap()

        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let allow = springboard.buttons["Allow"]
        if allow.waitForExistence(timeout: 10) { allow.tap() }

        let power = app.buttons["Connect"]
        XCTAssertTrue(power.waitForExistence(timeout: 20), "home screen did not appear")
        attach(app, "home")
        app.buttons["ip"].tap()
        XCTAssertTrue(app.buttons["ip"].staticTexts["IP"].waitForExistence(timeout: 5))
        sleep(4)
        attach(app, "home-ip")

        XCTAssertTrue(app.buttons["Check connection"].exists)
        app.buttons["More"].tap()
        app.buttons["Remove this device"].tap()
        app.buttons["Remove"].firstMatch.tap()
        XCTAssertTrue(app.textFields["pin"].waitForExistence(timeout: 15), "did not return to the PIN screen")
    }

    private func attach(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }
}
