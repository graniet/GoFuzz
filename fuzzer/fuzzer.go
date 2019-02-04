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
	Text string
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
		fmt.Printf("-----------\n")
		color.Yellow("%s %s\n", request.Type, request.Url)
		for key, value := range request.Header{
			fmt.Printf("%s : %s\n", key, value)
		}

		if len(request.Body) > 0{
			body := request.Body
			marsh, _ := json.Marshal(body)
			fmt.Printf("%s\n", string(marsh))
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
					marsh, _ = json.Marshal(body)
					req, err := http.NewRequest("POST", request.Url, bytes.NewBuffer(marsh))

					if err == nil{
						req.Header.Set("Content-Type", "application/json")
						client := &http.Client{}
						resp, err := client.Do(req)
						if err == nil {
							defer resp.Body.Close()
							//fmt.Println("response Status:", resp.Status)
							//fmt.Println("header: ", resp.Header)
							bodyT, _ := ioutil.ReadAll(resp.Body)
							//fmt.Println(string(body))
							if fuzz.Flags.Verbose {
								fmt.Printf("\033[2K\r%s", string(marsh))
								time.Sleep(300 * time.Millisecond)
							} else{
								fmt.Printf("\033[2K\rChecking payloads for parameter %s (%d/%d) %s",paramName, current,len(fuzz.Fuzzer.Payloads), loadingBase)
								time.Sleep(300 * time.Millisecond)
							}
							//fmt.Printf("%s\n", string(marsh))
							go fuzz.CheckDetector(string(bodyT), &request, paramName)
						}
					}

					current = current + 1
				}
				fmt.Println()
				body[paramName] = value
			}
			if len(request.Results) < 1{
				color.Blue("Results: (0) results found")
			} else{
				fmt.Println("Results: (" + strconv.Itoa(len(request.Results)) + ") results found")
				for _, detector := range request.Results{
					fmt.Printf("Possible %s found in %s with %s\n", fuzz.Fuzzer.Type, detector.Param, detector.Text)
				}
			}
		}
	}
	log.Printf("Fuzzing finish.")
	return true
}

func (fuzz *GoFuzz) CheckDetector(source string, request *Linker, param string){
	for _, detector := range fuzz.Fuzzer.Detector{
		if strings.Contains(strings.ToLower(source), strings.ToLower(detector)) {
			exist := false
			for _, detect := range request.Results{
				if detect.Text == detector && detect.Param == param{
					exist = true
				}
			}
			if exist == false {
				request.Results = append(request.Results, Result{Param: param, Text: detector})
			}
		}
	}
}