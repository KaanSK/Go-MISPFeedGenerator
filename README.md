# Go-MispFeedGenerator

Generate MISP feeds without a MISP Instance!

Go-MispFeedGenerator aka Go-MFG1000, is a library providing all functions needed to create events, adding attributes and generating needed feed files. Generated files can be consumed by any MISP instance.

Go-MispFeedGenerator has been created by manually reverse engineering [PyMisp-FeedGenerator]

Important Note: Go-MispFeedGenerator is not as sophisticated as [PyMisp] and [PyMisp-FeedGenerator]. For bugs and consumption issues on MISP, issue and pull requests are welcomed.

## Capabilities

* Create Event
  * Created event automatically gets a UUID and time fields
* Add attribute to Event with type and with optional category
  * If category is not provided, library fetches the [attributeTypes.json] from official pymisp repo and gets the first category including the type
  * If category is provided, library checks the type/category against [attributeTypes.json] from official pymisp repo
* Adding tags to event
* Generate Feed
  * Library can generate event json with naming convention "EventUUID.json"
* Generate Feed Metadata
  * Library can generate manifest.json and hashes.csv files alongside feed event
  * Library checks existing manifest.json, hashes.csv files. New feed data will be appended to existing ones. (Note: for event feed files like EventUUID.json, a new file will be generated each time. For multiple events, multiple EventUUID.json should exist)


## Usage
Install with:
````bash
go get github.com/KaanSK/Go-MISPFeedGenerator
````
Check [Test Code](mispfeedgenerator_test.go)  

```go
func TestFeedGenerationWithMetadata(t *testing.T) {
	defer cleanGeneratedFiles()
	event, err := NewMispEvent()
	if err != nil {
		t.Errorf("Could not create new event")
	}
	event.Info = "Dummy event"
	event.Orgc.Name = "TEST ORG"
	event.Orgc.UUID = "dc9de8b2-889c-42e5-a65f-68ecda38eed0"
	event.AddTag("type:OSINT", "#004646")
	event.AddTag("tlp:white", "#005151")

	event.AddAttribute("email-dst", "111test1@test.com", "Network activity")
	event.AddAttribute("btc", "111a3246asd8asd4a8asf5as8afs65fd77a", "")
	event.AddAttribute("md5", "111847356890723489034292345875234", "")

	err = event.GenerateFeed(true)
	if err != nil {
		t.Errorf("Could not generate feed with manifest and hashes. Error: %s", err)
	}

}
```



[PyMisp-FeedGenerator]: https://github.com/MISP/PyMISP/blob/main/examples/feed-generator/generate.py
[PyMisp]: https://github.com/MISP/PyMISP
[attributeTypes.json]: https://raw.githubusercontent.com/MISP/PyMISP/3c141e1fdb9127e10c5e7ec4784beb26af4b7ea7/pymisp/data/describeTypes.json