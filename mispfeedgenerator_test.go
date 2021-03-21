package mispfeedgenerator

import (
	"testing"
)

// TestNewEvent test instanciation of MispEvent Object
func TestNewEvent(t *testing.T) {
	_, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
}

// TestAddAttributewithNoCategory checks when attribute with no category
// is added, the first found category is automatically put
func TestAddAttributewithNoCategory(t *testing.T) {
	event, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
	event.Info = "Dummy event"
	event.Orgc.Name = "TEST ORG"
	event.Orgc.UUID = "dc9de8b2-889c-42e5-a65f-68ecda38eed0"

	err = event.AddAttribute("btc", "111a3246asd8asd4a8asf5as8afs65fd77a", "")

	if err != nil {
		t.Errorf("Could not add attribute")
	}
	if event.Attribute[0].Category == "" {
		t.Errorf("Category could not be put automatically for attribute")
	}
}

// TestAddTagsToEvent tests tag adding to event
func TestAddTagsToEvent(t *testing.T) {
	event, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
	event.Info = "Dummy event"
	event.Orgc.Name = "TEST ORG"
	event.Orgc.UUID = "dc9de8b2-889c-42e5-a65f-68ecda38eed0"
	event.AddTag("test", "#004646")
	event.AddTag("test2", "#005151")

	if len(event.Tag) != 2 {
		t.Errorf("Could not add tags")
	}
}

// TestAddAttributewithValidCategory checks when a valid category is put to attribute
// it passes the checking logic and stored in object
func TestAddAttributewithValidCategory(t *testing.T) {
	event, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
	event.Info = "Dummy event"
	event.Orgc.Name = "TEST ORG"
	event.Orgc.UUID = "dc9de8b2-889c-42e5-a65f-68ecda38eed0"

	err = event.AddAttribute("email-dst", "111test1@test.com", "Network activity")
	if err != nil {
		t.Errorf("Could not add attribute")
	}
	if event.Attribute[0].Category != "Network activity" {
		t.Errorf("Category could not be put automatically for attribute")
	}
}

// TestAddAttributewithValidCategory checks when a valid category is put to attribute
// it fails the checking logic and throws error
func TestAddAttributewithInvalidCategory(t *testing.T) {
	event, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
	event.Info = "Dummy event"
	event.Orgc.Name = "TEST ORG"
	event.Orgc.UUID = "dc9de8b2-889c-42e5-a65f-68ecda38eed0"

	err = event.AddAttribute("btc", "111a3246asd8asd4a8asf5as8afs65fd77a", "Network activity")
	if err == nil {
		t.Errorf("Type-Category check does not work")
	}
}

// TestFeedGenerationWithMetadata testing if feed with manifest.json and hashes.csv
// can be generated without errors. This test does not check the generated files.
func TestFeedGenerationWithMetadata(t *testing.T) {
	defer cleanGeneratedFiles()
	event, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
	event.Info = "Dummy event"
	event.Orgc.Name = "TEST ORG"
	event.Orgc.UUID = "dc9de8b2-889c-42e5-a65f-68ecda38eed0"

	event.AddTag("test", "#004646")
	event.AddTag("test2", "#005151")
	event.AddAttribute("email-dst", "111test1@test.com", "Network activity")
	event.AddAttribute("btc", "111a3246asd8asd4a8asf5as8afs65fd77a", "")
	event.AddAttribute("md5", "111847356890723489034292345875234", "")

	err = event.GenerateFeed(true)
	if err != nil {
		t.Errorf("Could not generate feed with manifest and hashes. Error: %s", err)
	}

}
