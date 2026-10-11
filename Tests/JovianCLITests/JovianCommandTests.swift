import Testing

@testable import JovianCLI

@Test func serveOptionsPreserveDefaultsAndTypedValues() throws {
    let defaults = try Serve.parse([])
    #expect(defaults.host == "127.0.0.1")
    #expect(defaults.port == 8080)
    #expect(defaults.apiHost == "127.0.0.1")
    #expect(defaults.apiPort == 8181)
    #expect(!defaults.captureSensitiveHeaders)
    #expect(defaults.requestHeaders.isEmpty)
    #expect(try defaults.credentials(environment: [:]) == nil)

    let command = try JovianCommand.parseAsRoot([
        "serve", "--host", "localhost", "--port=9000", "--api-host", "localhost", "--api-port", "9001",
        "--log", "/fixture/traffic.jsonl", "--har", "/fixture/traffic.har", "--capture-sensitive-headers",
        "--upload-bps", "1024", "--download-bps", "2048",
    ])
    let options = try #require(command as? Serve)
    #expect(options.host == "localhost")
    #expect(options.port == 9000)
    #expect(options.apiHost == "localhost")
    #expect(options.apiPort == 9001)
    #expect(options.logPath == "/fixture/traffic.jsonl")
    #expect(options.harPath == "/fixture/traffic.har")
    #expect(options.captureSensitiveHeaders)
    #expect(options.uploadBPS == 1024)
    #expect(options.downloadBPS == 2048)
}

@Test func serveOptionsPreserveRepeatedHeaderOrderAndColonValues() throws {
    let options = try Serve.parse([
        "--request-header", "X-Fixture: first", "--response-header", "X-Response: fixture:response",
        "--request-header", "X-Fixture: second",
    ])
    #expect(options.requestHeaders.map(\.name) == ["X-Fixture", "X-Fixture"])
    #expect(options.requestHeaders.map(\.value) == ["first", "second"])
    #expect(options.responseHeaders.map(\.value) == ["fixture:response"])
}

@Test func serveOptionsRejectMalformedArguments() {
    for arguments in [
        ["--port"], ["--port", "65536"], ["--port", "invalid"], ["--api-port", "65536"],
        ["--upload-bps", "0"], ["--download-bps=-1"], ["--request-header", "missing-colon"],
        ["--response-header", "missing-colon"], ["--unknown"], ["--proxy-user", "fixture"],
        ["--proxy-password-env", "FIXTURE_PASSWORD"],
    ] {
        #expect(throws: (any Error).self) { try Serve.parse(arguments) }
    }
}

@Test func serveOptionsReadPasswordOnlyFromTheSelectedEnvironmentVariable() throws {
    let options = try Serve.parse(["--proxy-user", "fixture", "--proxy-password-env", "FIXTURE_PASSWORD"])
    #expect(throws: (any Error).self) { try options.credentials(environment: [:]) }
    let credentials = try #require(try options.credentials(environment: ["FIXTURE_PASSWORD": "fixture-password"]))
    #expect(credentials.username == "fixture")
    #expect(credentials.password == "fixture-password")
}

@Test func serveOptionsExposeProxyTransportFeatures() throws {
    let command = try Serve.parse([
        "--downstream-proxy-url", "https://proxy.example.test:8443",
        "--request-timeout", "45", "--connect-timeout", "7", "--shutdown-grace", "2",
        "--generate-ca-cert", "--ca-output", "/fixture/authority.pem", "--tls-port", "4443",
        "--tls-server-name", "proxy.example.test", "--upstream-ca", "/fixture/origin-ca.pem",
        "--skip-tls-verify", "--proxy-name", "local-proxy",
    ])
    #expect(command.downstreamProxyURL == "https://proxy.example.test:8443")
    #expect(command.requestTimeout == 45)
    #expect(command.connectTimeout == 7)
    #expect(command.shutdownGrace == 2)
    #expect(command.generateCACert)
    #expect(command.caOutput == "/fixture/authority.pem")
    #expect(command.tlsPort == 4443)
    #expect(command.tlsServerName == "proxy.example.test")
    #expect(command.upstreamCA == "/fixture/origin-ca.pem")
    #expect(command.skipTLSVerify)
    #expect(command.proxyName == "local-proxy")
}

@Test func serveRejectsIncompleteTLSAndInvalidTransportOptions() {
    for arguments in [
        ["--request-timeout=-1"], ["--request-timeout", "nan"], ["--connect-timeout", "0"],
        ["--shutdown-grace", "infinity"], ["--proxy-name", "invalid name"],
        ["--generate-ca-cert", "--cert", "cert.pem", "--key", "key.pem"],
        ["--cert", "cert.pem"], ["--key", "key.pem"], ["--tls-port", "4443"],
        ["--ca-output", "authority.pem"], ["--downstream-proxy-url", "socks5://localhost:1080"],
        ["--downstream-proxy-url", "http://localhost/private/path"],
    ] {
        #expect(throws: (any Error).self) { try Serve.parse(arguments) }
    }
}
