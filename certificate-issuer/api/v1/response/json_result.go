package response

type JSONSuccessResult struct {
	Code          int         `json:"code" example:"200"`
	Message       string      `json:"message,omitempty" example:"Success"`
	Data          interface{} `json:"data,omitempty"`
	CorrelationId string      `json:"correlation_id,omitempty" example:"705e4dcb-3ecd-24f3-3a35-3e926e4bded5"`
}

type JSONFailureResult struct {
	Code          int         `json:"code" example:"400"`
	Data          interface{} `json:"data,omitempty"`
	Error         string      `json:"error,omitempty" example:"There was an error processing the request"`
	Stack         string      `json:"stacktrace,omitempty"`
	CorrelationId string      `json:"correlation_id,omitempty" example:"705e4dcb-3ecd-24f3-3a35-3e926e4bded5"`
}

type JSONNotFoundResult struct {
	Code          int         `json:"code" example:"404"`
	Data          interface{} `json:"data,omitempty"`
	Error         string      `json:"error,omitempty" example:"The server cannot find the requested resource"`
	Stack         string      `json:"stacktrace,omitempty"`
	CorrelationId string      `json:"correlation_id,omitempty" example:"705e4dcb-3ecd-24f3-3a35-3e926e4bded5"`
}
