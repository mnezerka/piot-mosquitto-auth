package handler

import (
    "encoding/json"
    "fmt"
    "net/http"
    "github.com/op/go-logging"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/bson"
    "piot-mosquitto-auth/model"
)

// Structure of HTTP body as received from mosquitto broker auth plugin
type MosquittoAuthUser struct {
    Username    string `json:"username"`
    Password    string `json:"password"`
}

type AuthenticateUser struct { }

func (h *AuthenticateUser) ServeHTTP(w http.ResponseWriter, r *http.Request) {

    ctx := r.Context()

    // check http method, POST is required
    if r.Method != http.MethodPost {
        http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
        return
    }

    // try to decode packet
    var packet MosquittoAuthUser
    if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    ctx.Value("log").(*logging.Logger).Debugf("Authenticating user %s", packet.Username)

    // first - try static users
    switch packet.Username {
    case "test":
        if ctx.Value("test-pwd") != "" &&  ctx.Value("test-pwd") == packet.Password {
            ctx.Value("log").(*logging.Logger).Debugf("User <%s> authenticated as static", packet.Username)
            return
        }
        ctx.Value("log").(*logging.Logger).Errorf("Static user <%s> authenticated failed ", packet.Username)
        http.Error(w, fmt.Sprintf("User identified as <%s> does not exist or provided credentials are wrong.", packet.Username), 401)
        return
    case "mon":
        if ctx.Value("mon-pwd") != "" &&  ctx.Value("mon-pwd") == packet.Password {
            ctx.Value("log").(*logging.Logger).Debugf("User <%s> authenticated as static", packet.Username)
            return
        }
        ctx.Value("log").(*logging.Logger).Errorf("Static user <%s> authenticated failed ", packet.Username)
        http.Error(w, fmt.Sprintf("User identified as <%s> does not exist or provided credentials are wrong.", packet.Username), 401)
        return
    case "piot":
        if ctx.Value("piot-pwd") != "" &&  ctx.Value("piot-pwd") == packet.Password {
            ctx.Value("log").(*logging.Logger).Debugf("User <%s> authenticated as static", packet.Username)
            return
        }
        ctx.Value("log").(*logging.Logger).Errorf("Static user <%s> authenticated failed ", packet.Username)
        http.Error(w, fmt.Sprintf("User identified as <%s> does not exist or provided credentials are wrong.", packet.Username), 401)
        return
    }

    // try to find org mqtt user in piot database
    db := ctx.Value("db").(*mongo.Database)

    var org model.Org
    collection := db.Collection("orgs")
    err := collection.FindOne(ctx, bson.M{"mqtt_username": packet.Username, "mqtt_password": packet.Password}).Decode(&org)
    if err != nil {
        ctx.Value("log").(*logging.Logger).Errorf(err.Error())
        http.Error(w, fmt.Sprintf("Mqtt credentials identified as <%s> do not exist or password does not match.", packet.Username), 401)
        return
    }

    ctx.Value("log").(*logging.Logger).Debugf("Authentication for credentials <%s> passed", packet.Username)
}
