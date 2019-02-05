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
)

type GoFuzz struct{
	Target string
	Mapper []Linker
	Fuzzer Vulnerability
	Flags Flag
}

type Linker struct{
	Type string `json:"type"`
	Url string `json:"url"`
	Header map[string]string `json:"header"`
	Body map[string]string `json:"body"`
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
}

func (fuzz *GoFuzz) Run(){
	log.Println("Running GoFuzz [v1.0] ...")
	if _, err := os.Stat(fuzz.Target); err != nil{
		log.Fatal("A error has occured with a target file.")
		return
	}

	err := fuzz.Fuzzer.LoadPayload()
	if err != nil{
		log.Println(err.Error())
		return
	}

	log.Println("Loading a request file...")
	err = fuzz.LoadMapper()
	if err != nil{
		log.Println(err.Error())
		return
	}

	log.Println(strconv.Itoa(len(fuzz.Mapper)) + " requests object loaded.")
	fuzz.Fuzzing()
}

func (fuzz *GoFuzz) LoadMapper() error{

	reader,_ := ioutil.ReadFile(fuzz.Target)
	err := json.Unmarshal(reader, &fuzz.Mapper)
	if err != nil{
		return errors.New("Error has occured with target file.")
	}

	if len(fuzz.Mapper) < 1{
		return errors.New("A target file is empty.")
	}

	return nil
}

func (fuzz *GoFuzz) Fuzzing() bool{
	log.Println("Fuzzing started")
	for _, request := range fuzz.Mapper{
		fmt.Printf("-----------\n| ")
		color.Yellow("%s %s\n", request.Type, request.Url)
		for key, value := range request.Header{
			fmt.Printf("| %s : %s\n", key, value)
		}

		if len(request.Body) > 0{
			body := request.Body
			marsh, _ := json.Marshal(body)
			fmt.Printf("| %s\n", string(marsh))
			fmt.Printf("-----------\n")
			for idx, value := range body{
				paramName := idx
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
					body[paramName] = payload
					marsh2, _ := json.Marshal(body)
					req, err := http.NewRequest(strings.ToUpper(request.Type), request.Url, bytes.NewBuffer(marsh2))

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
								fmt.Printf("\033[2K\r[%s] : %s",string(resp.Status), string(marsh2))
								time.Sleep(300 * time.Millisecond)
							} else{
								fmt.Printf("\033[2K\rChecking payloads for parameter %s (%d/%d) %s",paramName, current,len(fuzz.Fuzzer.Payloads), loadingBase)
								time.Sleep(300 * time.Millisecond)
							}

							go fuzz.CheckDetector(string(bodyT), &request, paramName, payload)
						}
					}

					current = current + 1
				}
				fmt.Println()
				body[paramName] = value
			}
			if len(request.Results) < 1{
				fmt.Println("Results: (0) results found")
			} else{
				fmt.Println("Results: (" + strconv.Itoa(len(request.Results)) + ") results found")
				for _, detector := range request.Results{
					color.Green("Possible %s found in %s with %s\n", strings.ToUpper(fuzz.Fuzzer.Type), detector.Param, detector.Payload.PayloadName)
				}
			}
		}
	}
	log.Printf("Fuzzing finish.")
	return true
}

func (fuzz *GoFuzz) CheckDetector(source string, request *Linker, param string, payload string){
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
				request.Results = append(request.Results, Result{Param: param, Payload: PayloadReq})
			}
		}
	}
}