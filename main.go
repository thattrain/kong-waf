package main

import (
	"embed"
	"fmt"
	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"log"
	"sync"
)

// region variables

//go:embed coraza.conf crs-setup.conf rules
var embedFS embed.FS
var wafMap map[Config]coraza.WAF = make(map[Config]coraza.WAF)
var wafLock sync.Mutex

const (
	PluginName = "Kong WAF"
	Version    = "0.0.1"
	Priority   = 909 // less than rate-limiting plugin(910)

	corazaConf = "coraza.conf"
	crsConf    = "crs-setup.conf"
	coreRules  = "rules/*.conf"

	// base rules need to be included when EnableAll in Config is false
	csrInitRule            = "rules/REQUEST-901-INITIALIZATION.conf"
	blockingEvaluationRule = "rules/REQUEST-949-BLOCKING-EVALUATION.conf"
	correlationRules       = "rules/RESPONSE-980-CORRELATION.conf"

	// protection strategy
	scannerDetectionRules = "rules/REQUEST-913-SCANNER-DETECTION.conf"
	multipartRules        = "rules/REQUEST-922-MULTIPART-ATTACK.conf"
	rceRules              = "rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf"
	phpRules              = "rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf"
	genericRules          = "rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf"
	xssRules              = "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"
	sqlInjectionRules     = "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
	sessionFixationRules  = "rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"
	javaRules             = "rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf"
	webShellRules         = "rules/RESPONSE-955-WEB-SHELLS.conf"
)

//endregion variables

func New() interface{} {
	//todo: initialize config with some default value
	config := &Config{}
	return config
}

func main() {
	err := server.StartServer(New, Version, Priority)
	if err != nil {
		log.Fatalf("Failed to start %s plugin", PluginName)
	}
}

func (conf Config) Access(kong *pdk.PDK) {
	wafLock.Lock()
	defer wafLock.Unlock()

	// get waf instance base on Config struct
	waf, exist := wafMap[conf]
	if exist {
		kong.Log.Debug(fmt.Printf("WAF instance with config %v exist - Not create again", conf))
		// transaction handling
		var tx types.Transaction
		requestId, err := kong.Request.GetHeader("X-Kong-Request-Id")
		if err != nil {
			tx = waf.NewTransaction()
		} else {
			//map Kong requestId with Coraza requestId
			tx = waf.NewTransactionWithID(requestId)
		}

		defer func() {
			tx.ProcessLogging()
			tx.Close()
		}()

		interruption, requestErr := processRequest(tx, kong)
		if requestErr != nil {
			kong.Response.ExitStatus(403)
			kong.Response.Exit(403, []byte("Error in WAF, check your security rules."), nil)
		}

		if interruption != nil {
			interruptionType := interruption.Action
			interruptionId := interruption.RuleID
			response := fmt.Sprintf("Request terminated by Kong WAF - Action: %s - RuleId: %d", interruptionType, interruptionId)
			kong.Response.Exit(403, []byte(response), nil)
		}
	} else {
		wafInstance, err := createWaf(conf)
		if err != nil {
			kong.Log.Err("Error while creating kong WAF instance", err)
			panic(err)
		}
		wafMap[conf] = wafInstance
		kong.Log.Debug(fmt.Sprintf("Create WAF instance created with config %v", conf))
		// transaction handling
		var tx types.Transaction
		requestId, err := kong.Request.GetHeader("X-Kong-Request-Id")
		if err != nil {
			tx = wafInstance.NewTransaction()
		} else {
			//map Kong requestId with Coraza requestId
			tx = wafInstance.NewTransactionWithID(requestId)
		}

		defer func() {
			tx.ProcessLogging()
			tx.Close()
		}()

		interruption, requestErr := processRequest(tx, kong)
		if requestErr != nil {
			kong.Response.ExitStatus(403)
			kong.Response.Exit(403, []byte("Error in WAF, check your security rules."), nil)
		}

		if interruption != nil {
			interruptionType := interruption.Action
			interruptionId := interruption.RuleID
			response := fmt.Sprintf("Request terminated by Kong WAF - Action: %s - RuleId: %d", interruptionType, interruptionId)
			kong.Response.Exit(403, []byte(response), nil)
		}
	}

}
