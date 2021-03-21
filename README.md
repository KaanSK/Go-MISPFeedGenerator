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
* Generate Feed
  * Library can generate event json with naming convention "EventUUID.json"
* Generate Feed Metadata
  * Library can generate manifest.json and hashes.csv files alongside feed event
  * Library checks existing manifest.json, hashes.csv files. New feed data will be appended to existing ones. (Note: for event feed files like EventUUID.json, a new file will be generated each time. For multiple events, multiple EventUUID.json should exist)


## Usage
Check [Test Code](mispfeedgenerator_test.go)  



[PyMisp-FeedGenerator]: https://github.com/MISP/PyMISP/blob/main/examples/feed-generator/generate.py
[PyMisp]: https://github.com/MISP/PyMISP
[attributeTypes.json]: https://raw.githubusercontent.com/MISP/PyMISP/3c141e1fdb9127e10c5e7ec4784beb26af4b7ea7/pymisp/data/describeTypes.json