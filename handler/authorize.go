package handler

import (
    "encoding/json"
    "fmt"
    "net/http"
    "github.com/op/go-logging"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "piot-mosquitto-auth/utils"
    "piot-mosquitto-auth/model"
)

type MosquittoAuthAcl struct {
    Acc         int `json:"acc"`
    ClientId    string `json:"clientid"`
    Topic       string `json:"topic"`
    Username    string `json:"username"`
}

// Represents org as stored in database
type Org struct {
    Id          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
    Name        string `json:"name"`
}

type Authorize struct { }

func (h *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {

    // check http method, POST is required
    if r.Method != http.MethodPost {
        http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
        return
    }

    // try to decode packet
    var packet MosquittoAuthAcl
    if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    ctx := r.Context()
    ctx.Value("log").(*logging.Logger).Debugf("Acl request for user %s, topic: %s, client: %s, access type: %d", packet.Username, packet.Topic, packet.ClientId, packet.Acc)

    // first, try to check static users
    switch packet.Username {
    case "test":
        if utils.GetMqttRootTopic(packet.Topic) == "test" {
            ctx.Value("log").(*logging.Logger).Debugf("Authorization passed for static user <%s> and topic <%s>", packet.Username, packet.Topic)
            return
        }
        ctx.Value("log").(*logging.Logger).Errorf("Authorization rejected for static user <%s> and topic <%s>", packet.Username, packet.Topic)
        http.Error(w, fmt.Sprintf("Authorization rejected for static user <%s> and topic <%s>", packet.Username, packet.Topic), 401)
        return
    case "mon":
        // TODO check also Acc attribute to allow only read
        if utils.GetMqttRootTopic(packet.Topic) == "$SYS" {
            ctx.Value("log").(*logging.Logger).Debugf("Authorization passed for static user <%s> and topic <%s>", packet.Username, packet.Topic)
            return
        }
        ctx.Value("log").(*logging.Logger).Errorf("Authorization rejected for static user <%s> and topic <%s>", packet.Username, packet.Topic)
        http.Error(w, fmt.Sprintf("Authorization rejected for static user <%s> and topic <%s>", packet.Username, packet.Topic), 401)
        return
    case "piot":
        if utils.GetMqttRootTopic(packet.Topic) == "org" {
            ctx.Value("log").(*logging.Logger).Debugf("Authorization passed for static user <%s> and topic <%s>", packet.Username, packet.Topic)
            return
        }
        ctx.Value("log").(*logging.Logger).Errorf("Authorization rejected for static user <%s> and topic <%s>", packet.Username, packet.Topic)
        http.Error(w, fmt.Sprintf("Authorization rejected for static user <%s> and topic <%s>", packet.Username, packet.Topic), 401)
        return
    }

    // reject org name
    topicOrgName := utils.GetMqttTopicOrg(packet.Topic)

    // reject all topics with empty org name
    if topicOrgName == "" {
        ctx.Value("log").(*logging.Logger).Errorf("Reject empty org name for topic %s -> authorization failed", packet.Topic)
        http.Error(w, fmt.Sprintf("Empty organization is not accepted (topic: %s)", packet.Topic), 401)
    }

    ctx.Value("log").(*logging.Logger).Debugf("Look for org mqtt user idetified as <%s>", packet.Username)

    // find all orgs were configured mqtt user matches the one received from mosquitto
    // this is because same mqtt credentials could be configured in more than one org
    db := ctx.Value("db").(*mongo.Database)
    collection := db.Collection("orgs")
    cur, err := collection.Find(ctx, bson.M{"mqtt_username": packet.Username})
    if err != nil {
        ctx.Value("log").(*logging.Logger).Errorf("GQL: error : %v", err)
        return
    }
    defer cur.Close(ctx)

    // loop through all orgs that were found
    for cur.Next(ctx) {
        ctx.Value("log").(*logging.Logger).Infof("Iteration")

        // To decode into a struct, use cursor.Decode()
        org := model.Org{}
        err := cur.Decode(&org)
        if err != nil {
            ctx.Value("log").(*logging.Logger).Errorf("GQL: error : %v", err)
            return
        }

        ctx.Value("log").(*logging.Logger).Infof("Iteration org %s %s", org.Name, topicOrgName)

        // if currently iterated org matches the one from mosquitto topic
        if org.Name == topicOrgName {
            ctx.Value("log").(*logging.Logger).Debugf("Topic is matching org mqtt user (%s) -> authorization passed", packet.Topic)
            return
        }
    }

    ctx.Value("log").(*logging.Logger).Debugf("No org mqtt user matching topic %s -> authorization failed", packet.Topic)
    http.Error(w, fmt.Sprintf("No valid mqtt credentials found for organization %s", topicOrgName), 401)
}
