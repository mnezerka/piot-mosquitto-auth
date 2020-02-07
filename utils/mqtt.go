package utils

import (
    "strings"
)

func GetMqttRootTopic(topic string) string {
    if idx := strings.IndexByte(topic, '/'); idx >= 0 {
        return topic[:idx]
    }
    return topic
}

func GetMqttTopicOrg(topic string) string {
    if parts := strings.Split(topic, "/"); len(parts) >= 2 {
        return parts[1]
    }
    return ""
}
