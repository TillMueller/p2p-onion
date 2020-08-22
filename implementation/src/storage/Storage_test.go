package storage

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

func wait(notifyGroups *NotifyGroups, id int, waitKey string) {
	fmt.Println("Start waiting, key " + waitKey + ", id " + strconv.Itoa(id))
	WaitForNotifyGroup(notifyGroups, waitKey, 0)
	fmt.Println("Got woken up, key " + waitKey + ", id " + strconv.Itoa(id))
}

func TestSynchronization(t *testing.T) {
	notifyGroups := InitNotifyGroups()
	for i := 0; i < 2; i++ {
		go wait(notifyGroups, i, "group0")
	}
	for i := 2; i < 4; i++ {
		go wait(notifyGroups, i, "group1")
	}

	BroadcastNotifyGroup(notifyGroups, "group1")
	time.Sleep(time.Second)
	BroadcastNotifyGroup(notifyGroups, "group0")
	time.Sleep(time.Second)
	CleanupNotifyGroup(notifyGroups, "group0")
	CleanupNotifyGroup(notifyGroups, "group1")
}