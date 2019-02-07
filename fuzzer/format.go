package fuzzer

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

type FormatPostMan struct{
	Requests []FormatPostManRequest `json:"requests"`
}

type FormatPostManRequest struct{
	Type string `json:"method"`
	Url string `json:"url"`
	Header []FormatPostManHeader `json:"headerData"`
	Body interface{} `json:"rawModeData"`
	Results []Result
}

type FormatPostManHeader struct{
	Key string `json:"key"`
	Type string `json:"type"`
	Value string `json:"value"`
}
