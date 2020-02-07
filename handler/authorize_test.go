package handler_test

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "piot-mosquitto-auth/test"
    "piot-mosquitto-auth/handler"
)

func TestAuthorizeUnknownUser(t *testing.T) {
    ctx := test.CreateTestContext()

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"hello",
        "username":"test@test.com"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()

    handler := handler.Authorize{}

    handler.ServeHTTP(rr, req)

    test.CheckStatusCode(t, rr, 401)
}

func TestAuthorizeStaticUserTest(t *testing.T) {
    ctx := test.CreateTestContext()

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"hello",
        "username":"test"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()
    handler := handler.Authorize{}
    handler.ServeHTTP(rr, req)
    test.CheckStatusCode(t, rr, 401)

    deviceData = `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"test/xx",
        "username":"test"
    }`

    req, err = http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr = httptest.NewRecorder()
    handler.ServeHTTP(rr, req)
    test.CheckStatusCode(t, rr, 200)
}

func TestAuthorizeStaticUserMon(t *testing.T) {
    ctx := test.CreateTestContext()

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"hello",
        "username":"mon"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()
    handler := handler.Authorize{}
    handler.ServeHTTP(rr, req)
    test.CheckStatusCode(t, rr, 401)

    deviceData = `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"$SYS/XYZ",
        "username":"mon"
    }`

    req, err = http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr = httptest.NewRecorder()
    handler.ServeHTTP(rr, req)
    test.CheckStatusCode(t, rr, 200)
}

func TestAuthorizeStaticUserPiot(t *testing.T) {
    ctx := test.CreateTestContext()

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"hello",
        "username":"piot"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()
    handler := handler.Authorize{}
    handler.ServeHTTP(rr, req)
    test.CheckStatusCode(t, rr, 401)

    deviceData = `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"org/Adidas",
        "username":"piot"
    }`

    req, err = http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr = httptest.NewRecorder()
    handler.ServeHTTP(rr, req)
    test.CheckStatusCode(t, rr, 200)
}

func TestAuthorizeUserFromDb(t *testing.T) {
    ctx := test.CreateTestContext()
    test.CleanDb(t, ctx)
    test.CreateOrg(t, ctx, "SomeOrg")

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"org/SomeOrg/hello",
        "username":"tester"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()

    handler := handler.Authorize{}

    handler.ServeHTTP(rr, req)

    test.CheckStatusCode(t, rr, 200)
}

// This verifies that known user (credentials could be valid
// for other org) is rejected if he/she tries to send
// to unknown org org
func TestAuthorizeUserFromDbForUnknownOrg(t *testing.T) {
    ctx := test.CreateTestContext()
    test.CleanDb(t, ctx)
    test.CreateOrg(t, ctx, "SomeOrg")

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"org/UnknownOrg/hello",
        "username":"tester"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()

    handler := handler.Authorize{}

    handler.ServeHTTP(rr, req)

    test.CheckStatusCode(t, rr, 401)
}

// This verifies that unknown user is rejected if he/she
// tries to send to not known org
func TestAuthorizeUnknownUserFromDbForOrg(t *testing.T) {
    ctx := test.CreateTestContext()
    test.CleanDb(t, ctx)
    test.CreateOrg(t, ctx, "SomeOrg")

    deviceData := `
    {
        "acc":2,
        "clientid":"mqtt-client",
        "topic":"org/SomeOrg/hello",
        "username":"testerx"
    }`

    req, err := http.NewRequest("POST", "/", strings.NewReader(deviceData))
    test.Ok(t, err)

    req = req.WithContext(ctx)
    rr := httptest.NewRecorder()

    handler := handler.Authorize{}

    handler.ServeHTTP(rr, req)

    test.CheckStatusCode(t, rr, 401)
}

