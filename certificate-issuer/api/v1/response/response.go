package response

import (
	"fmt"
	"math"
	"net/http"

	"certificate-issuer/configuration"

	"github.com/coderollers/go-utils"
	"github.com/gin-gonic/gin"
)

func SuccessResponse(c *gin.Context, data interface{}) {
	c.IndentedJSON(http.StatusOK, JSONSuccessResult{
		Code:          http.StatusOK,
		Data:          data,
		Message:       "Success",
		CorrelationId: c.MustGet(configuration.CorrelationIdKey).(string),
	})
}

func FailureResponse(c *gin.Context, data interface{}, err utils.HttpError) {
	if err.Err == nil {
		err = utils.HttpError{Code: int(math.Max(float64(err.Code), 500)), Err: fmt.Errorf("FailureResponse was called with a nil error (%s)", err.Message)}
	}
	c.IndentedJSON(err.Code, JSONFailureResult{
		Code:          err.Code,
		Data:          data,
		Error:         err.Error(),
		Stack:         err.StackTrace(),
		CorrelationId: c.MustGet(configuration.CorrelationIdKey).(string),
	})
}
