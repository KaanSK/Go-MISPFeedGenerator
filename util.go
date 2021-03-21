package mispfeedgenerator

import (
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

func getJSON(url string, target interface{}) error {
	requestClient := &http.Client{Timeout: 10 * time.Second}
	r, err := requestClient.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	err = json.Unmarshal(body, target)
	return err
}

func getHash(data string) (string, error) {
	algorithm := md5.New()
	_, err := algorithm.Write([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(algorithm.Sum(nil)), nil
}

func mergeMaps(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

func writeStructToFile(obj map[string]interface{}, fileName string) (err error) {
	file, _ := json.MarshalIndent(obj, "", " ")
	if err := ioutil.WriteFile(fileName, file, 0644); err != nil {
		return err
	}
	return
}

func createHashesFile(me event) (err error) {
	var data = [][]string{}
	for _, att := range me.Attribute {
		data = append(data, []string{att._hash, me.UUID})
	}
	file, err := os.OpenFile("hashes.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, value := range data {
		_ = writer.Write(value)
	}
	return
}

func createManifestFile(me event) (err error) {
	if _, err := os.Stat("manifest.json"); os.IsNotExist(err) {
		err = writeStructToFile(me._manifest, "manifest.json")
		if err != nil {
			return err
		}
	} else {
		data, err := ioutil.ReadFile("manifest.json")
		if err != nil {
			return err
		}
		existingManifests := make(map[string]interface{})
		err = json.Unmarshal([]byte(data), &existingManifests)
		if err != nil {
			return err
		}

		finalManifest := mergeMaps(existingManifests, me._manifest)
		err = writeStructToFile(finalManifest, "manifest.json")
		if err != nil {
			return err
		}
	}
	return
}

func createEventFile(feedEvent map[string]interface{}) (err error) {
	uuid := feedEvent["Event"].(*event).UUID
	fileName := fmt.Sprintf("%s.json", uuid)
	err = writeStructToFile(feedEvent, fileName)
	if err != nil {
		return err
	}
	return
}

func normalizeFieldName(fieldName string) string {
	var g []string
	p := strings.Fields(fieldName)
	for _, value := range p {
		g = append(g, strings.Title(value))
	}
	return strings.Join(g, "")
}

func getAttr(obj interface{}, fieldName string) reflect.Value {
	fieldName = normalizeFieldName(fieldName)
	pointToStruct := reflect.ValueOf(obj) // addressable
	curStruct := pointToStruct.Elem()
	if curStruct.Kind() != reflect.Struct {
		panic("not struct")
	}
	curField := curStruct.FieldByName(fieldName) // type: reflect.Value
	if !curField.IsValid() {
		panic("not found:" + fieldName)
	}
	return curField
}

func cleanGeneratedFiles() {
	feedJsons, _ := filepath.Glob("*json")
	metadata, _ := filepath.Glob("*csv")
	createdFiles := append(feedJsons, metadata...)

	for _, f := range createdFiles {
		if err := os.Remove(f); err != nil {
			panic(err)
		}
	}
}
