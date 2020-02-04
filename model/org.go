package model

import(
    "go.mongodb.org/mongo-driver/bson/primitive"
)

// Represents org as stored in piot database
type Org struct {
    Id primitive.ObjectID `json:"id" bson:"_id,omitempty"`
    Name         string `json:"name"`
    MqttUsername string `json:"mqtt_username"`
    MqttPassword string `json:"mqtt_password"`
}

