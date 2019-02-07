package fuzzer

import (
	"os"
	"io/ioutil"
	"encoding/json"
	"log"
	"github.com/pkg/errors"
	"github.com/fatih/color"
	"strconv"
	"strings"
	"fmt"
	"net/http"
	"bytes"
	"time"
	"reflect"
	"github.com/tidwall/sjson"
)

type GoFuzz struct{
	Target string
	Mapper []Linker
	MapperComplex []LinkerV2
	Fuzzer Vulnerability
	ParamUsed map[string]string
	Flags Flag
	CustomPayload string
}

type Linker struct{
	Type string `json:"type"`
	Url string `json:"url"`
	Header map[string]string `json:"header"`
	Body map[string]string `json:"body"`
	Results []Result
}

type LinkerV2 struct{
	Type string `json:"type"`
	Url string `json:"url"`
	Header map[string]string `json:"header"`
	Body interface{} `json:"body"`
	Results []Result
}

type Result struct{
	Param string
	Payload ResultPayload
}

type ResultPayload struct{
	PayloadName string
	PayloadText string
}

type Flag struct{
	Verbose bool
	Complex bool
}

func (fuzz *GoFuzz) LoadMapper() (error){
	reader,_ := ioutil.ReadFile(fuzz.Target)
	err := json.Unmarshal(reader, &fuzz.MapperComplex)
	if err != nil{
		return errors.New(err.Error())
	}
	return nil
}

func (fuzz *GoFuzz) CheckParam(param string) bool{
	for _, value := range fuzz.ParamUsed{
		if value == param{
			return true
		}
	}
	return false
}

func (fuzz *GoFuzz) Run(){
	log.Println("Running GoFuzz [v1.0] ...")
	if _, err := os.Stat(fuzz.Target); err != nil{
		log.Fatal("A error has occured with a target file.")
		return
	}

	if fuzz.CustomPayload != ""{
		err := fuzz.Fuzzer.CustomPayload(fuzz.CustomPayload)
		if err != nil{
			log.Println(err.Error())
			return
		}
	} else{
		err := fuzz.Fuzzer.LoadPayload()
		if err != nil{
			log.Println(err.Error())
			return
		}
	}

	log.Println("Loading a request file...")
	err := fuzz.LoadMapper()
	log.Println(strconv.Itoa(len(fuzz.MapperComplex)) + " requests object loaded.")
	fuzz.Fuzzing()
	if err != nil{
		log.Println(err.Error())
		return
	}
}

func (fuzz *GoFuzz) Foreach(element map[string]interface{}, preface string){

	for vName := range element{
		nextPreface := ""
		if strings.Contains(reflect.TypeOf(element[vName]).String(), "map["){
			nextPreface = preface + vName + "."
			currentElement := element[vName].(map[string]interface{})
			fuzz.Foreach(currentElement, nextPreface)
		}
	}
	for vName := range element{
		if !strings.Contains(reflect.TypeOf(element[vName]).String(), "map") {
			fuzz.ParamUsed[strconv.Itoa(len(fuzz.ParamUsed))+"_param"] = preface + vName
		}
	}
}

func (fuzz *GoFuzz) Fuzzing() error{

	reader,_ := ioutil.ReadFile(fuzz.Target)
	err := json.Unmarshal(reader, &fuzz.MapperComplex)
	if err != nil{
		return errors.New(err.Error())
	}
	log.Println("Fuzzing started")
	for _, request := range fuzz.MapperComplex{
		fmt.Printf("-----------\n| ")
		color.Yellow("%s %s\n", request.Type, request.Url)
		for key, value := range request.Header{
			fmt.Printf("| %s : %s\n", key, value)
		}
		object := request.Body.(map[string]interface{})
		if len(object) > 0{
			fuzz.Foreach(object, "")
			marsh, _ := json.Marshal(object)
			fmt.Printf("| %s\n", string(marsh))
			fmt.Printf("-----------\n")
			for _, parameters := range fuzz.ParamUsed{
				loadingBase := "-"
				current := 1
				for _, payload := range fuzz.Fuzzer.Payloads {
					if loadingBase == "-"{
						loadingBase = "/"
					} else if loadingBase == "/"{
						loadingBase = "\\"
					} else {
						loadingBase = "-"
					}
					marsh2, _ := json.Marshal(object)
					value, _ := sjson.Set(string(marsh2), parameters, payload)
					req, err := http.NewRequest(strings.ToUpper(request.Type), request.Url, bytes.NewBuffer([]byte(value)))
					if err == nil{
						for key, value := range request.Header{
							req.Header.Set(key, value)
						}
						client := &http.Client{}
						resp, err := client.Do(req)
						if err == nil {
							defer resp.Body.Close()

							bodyT, _ := ioutil.ReadAll(resp.Body)
							if fuzz.Flags.Verbose {
								fmt.Printf("\033[2K\r[%s] : %s",string(resp.Status), string(value))
								time.Sleep(300 * time.Millisecond)
							} else{
								fmt.Printf("\033[2K\rChecking payloads for parameter %s (%d/%d) %s",parameters, current,len(fuzz.Fuzzer.Payloads), loadingBase)
								time.Sleep(300 * time.Millisecond)
							}

							go fuzz.CheckDetector(string(bodyT), &request, parameters, payload)
						} else{
							fmt.Println(err.Error())
							break
						}
					}

					current = current + 1
				}
			}
		}
	}
	log.Printf("Fuzzing finish.")
	return nil
}

func (fuzz *GoFuzz) CheckDetector(source string, request *LinkerV2, param string, payload string){
	for _, detector := range fuzz.Fuzzer.Detector{
		if strings.Contains(strings.ToLower(source), strings.ToLower(detector)) {
			exist := false
			PayloadReq := ResultPayload{}
			PayloadReq.PayloadName = payload
			PayloadReq.PayloadText = strings.TrimSpace(detector)

			for _, detect := range request.Results{
				if detect.Payload.PayloadText == strings.TrimSpace(detector) && detect.Param == param{
					exist = true
				}
			}
			if exist == false {
				color.Green("\033[2K\rResults found in '%s' with payload `%s` => %s\n",param,  PayloadReq.PayloadName, PayloadReq.PayloadText)
				request.Results = append(request.Results, Result{Param: param, Payload: PayloadReq})
			}
		}
	}
}