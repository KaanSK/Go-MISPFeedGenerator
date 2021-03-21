// Package mispfeedgenerator used to generate MISP feeds without an instance.
package mispfeedgenerator

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

// getAttributeTypes Fetches official Attribute types and categories from
// https://raw.githubusercontent.com/MISP/PyMISP/main/pymisp/data/describeTypes.json
func getAttributeTypes() (attType attributeTypes, err error) {
	attTypes := attributeTypes{}
	err = getJSON("https://raw.githubusercontent.com/MISP/PyMISP/main/pymisp/data/describeTypes.json", &attTypes)
	return attTypes, err
}

// NewMispEvent Used to instantiate a MISP event
func NewMispEvent() (event, error) {
	mispEvent := event{}
	fetchedAttTypes, err := getAttributeTypes()
	if err != nil {
		return mispEvent, err
	}

	mispEvent._attributeTypes = fetchedAttTypes
	mispEvent._fieldsForFeed = []string{"uuid", "info", "threat_level_id", "analysis", "timestamp", "publish_timestamp", "published", "date", "extends_uuid"}
	mispEvent.UUID = uuid.NewString()
	mispEvent.Published = true
	mispEvent.Tag = []tag{}

	currentTime := time.Now()
	currentTimestamp := fmt.Sprint(currentTime.Unix())

	mispEvent.Date = currentTime.UTC().Format("2006-01-02")
	mispEvent.PublishTimestamp = currentTimestamp
	mispEvent.StrTimestamp = currentTimestamp

	return mispEvent, nil
}

// validateAttributeType Used to validate attribute type against categories provided in
// https://raw.githubusercontent.com/MISP/PyMISP/main/pymisp/data/describeTypes.json
func (me *event) validateAttributeType(data string) bool {
	for _, value := range me._attributeTypes.Result.Types {
		if value == data {
			return true
		}
	}
	return false
}

// GenerateFeed used to generate feed files. 'withMeta' parameter should be true when
// hashes.csv and manifest.json is needed.
//
// It automatically checks if there are files generated before and appends manifest.json,
// hashes.csv to existing ones.
func (me *event) GenerateFeed(withMeta bool) (err error) {
	if me.Info == "" || me.Orgc == (orgc{}) {
		return errors.New("Info or Orgc fields can not be empty")
	}
	if me.Orgc.UUID == "" {
		me.Orgc.UUID = uuid.NewString()
	}
	// analysis: 0 means initial, 1 ongoing, 2 completed
	if me.Analysis == 0 {
		me.Analysis = 2
	}

	if me.ThreatLevelID == 0 {
		me.ThreatLevelID = 4
	}

	err = me.computeHashFieldsForAttributes()
	if err != nil {
		return err
	}

	me._manifest = map[string]interface{}{
		me.UUID: map[string]interface{}{
			"Orgc":            me.Orgc,
			"Tag":             me.Tag,
			"info":            me.Info,
			"date":            me.Date,
			"analysis":        me.Analysis,
			"threat_level_id": me.ThreatLevelID,
			"timestamp":       me.StrTimestamp,
		},
	}
	feedEvent := map[string]interface{}{
		"Event": me,
	}

	err = createEventFile(feedEvent)
	if err != nil {
		return err
	}

	if withMeta {
		err = createManifestFile(*me)
		if err != nil {
			return err
		}
		err = createHashesFile(*me)
		if err != nil {
			return err
		}
	}

	return

}

func (me *event) computeHashFieldsForAttributes() (err error) {
	hashes := []string{}
	for idx, att := range me.Attribute {
		if strings.Contains(att.Type, "|") || att.Type == "malware-sample" {
			for _, data := range strings.Split(att.Value, "|") {
				computedHash, err := getHash(data)
				if err != nil {
					return err
				}
				me.Attribute[idx]._hash = computedHash
				hashes = append(hashes, computedHash)
			}
		} else {
			computedHash, err := getHash(att.Value)
			if err != nil {
				return err
			}
			me.Attribute[idx]._hash = computedHash
			hashes = append(hashes, computedHash)
		}
	}
	me._hashes = hashes
	return
}

func (me *event) getAttributeCategory(attType string) string {
	v := reflect.ValueOf(me._attributeTypes.Result.CategoryTypeMappings)
	for i := 0; i < v.NumField(); i++ {
		val := v.Field(i).Interface().([]string)
		for _, value := range val {
			if value == attType {
				return v.Type().Field(i).Name
			}
		}
	}
	return ""
}

func (me *event) checkTypeCategory(attType string, category string) bool {
	categoryTypeMappings := me._attributeTypes.Result.CategoryTypeMappings

	typesInCategory := getAttr(&categoryTypeMappings, category)
	for _, typeInCategory := range typesInCategory.Interface().([]string) {
		if typeInCategory == attType {
			return true
		}
	}
	return false
}

func (me *event) AddAttribute(dataType string, data string, category string) (err error) {
	if category != "" {
		if !me.checkTypeCategory(dataType, category) {
			return errors.New("Datatype does not belong to Category")
		}
	} else {
		category = me.getAttributeCategory(dataType)
	}

	dataTypeExists := me.validateAttributeType(dataType)
	if !dataTypeExists {
		return errors.New("Datatype does not exist")
	}

	att := newAttribute()
	att.UUID = uuid.NewString()
	att.StrTimestamp = me.StrTimestamp
	dataType = strings.ToLower(dataType)
	att.Value = data
	att.Type = dataType
	att.Category = category
	me.Attribute = append(me.Attribute, att)

	return nil
}

func (me *event) AddTag(name string, colour string) {
	tag := tag{Name: name, Colour: colour}
	me.Tag = append(me.Tag, tag)
}

func newAttribute() attribute {
	att := attribute{}
	att._fieldsForFeed = []string{"uuid", "value", "category", "type", "comment", "data", "deleted", "timestamp", "to_ids", "disable_correlation", "first_seen", "last_seen"}
	return att
}
