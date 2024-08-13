package main

import (
	"fmt"
	"github.com/Kong/go-pdk"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"regexp"
)

const (
	// SecRuleEngine
	//value of SecRuleEngine reference from: https://coraza.io/docs/seclang/directives/#secruleengine
	secRuleEngineRegex           = `(?m)(^(?<indent>\s*)?(?<key>SecRuleEngine\s+)(?<value>\w+)$)`
	secRuleEngineValueDetectOnly = "DetectionOnly"
	secRuleEngineEnforce         = "On"
	secRuleEngineOff             = "Off"

	// SecDebugLog
	//value of SecRuleEngine reference from: https://coraza.io/docs/seclang/directives/#secdebuglog
	secDebugLogPathRegex  = `(?m)(^(?<indent>\s*)?(?<key>SecDebugLog\s+)(?<value>.*)$)`
	secDebugLogLevelRegex = `(?m)(^(?<indent>\s*)?(?<key>SecDebugLogLevel\s+)(?<value>[1-9])$)`
)

func createWafConfig(conf Config) coraza.WAFConfig {

	corazaRules := loadFile(corazaConf)
	secEngineRegex := regexp.MustCompile(secRuleEngineRegex)
	if conf.DetectionMode {
		corazaRules = secEngineRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", secRuleEngineValueDetectOnly))
	} else if conf.EnforceMode {
		corazaRules = secEngineRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", secRuleEngineEnforce))
	} else {
		corazaRules = secEngineRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", secRuleEngineOff))
	}

	if conf.LogPath != "" {
		err := createFile(conf.LogPath)
		if err != nil {
			fmt.Printf("Error creating log file: %v", err)
		} else {
			secDebugLogPathRegex := regexp.MustCompile(secDebugLogPathRegex)
			corazaRules = secDebugLogPathRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", conf.LogPath))
		}
	}

	if conf.LogLevel != 0 {
		secDebugLogLevelRegex := regexp.MustCompile(secDebugLogLevelRegex)
		corazaRules = secDebugLogLevelRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%d", conf.LogLevel))
	}

	//fmt.Printf("newCorazaRules: %v\n", corazaRules)

	// order of directives must be in correct order in compile time
	wafConfig := coraza.NewWAFConfig().
		WithRootFS(embedFS).
		WithDirectives(corazaRules).
		WithDirectivesFromFile(crsConf).
		WithErrorCallback(logWafError)

	if conf.EnableAll {
		fmt.Println("Create WAF instance with all rules enable")
		wafConfig = wafConfig.WithDirectivesFromFile(coreRules)
	} else {
		// order of directives must be in correct order in compile time
		// init core rule set
		wafConfig = wafConfig.WithDirectivesFromFile(csrInitRule)
		if conf.ScannerDetection {
			wafConfig = wafConfig.WithDirectivesFromFile(scannerDetectionRules)
		}
		if conf.MultipartProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(multipartRules)
		}
		if conf.PhpProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(phpRules)
		}
		if conf.RceProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(rceRules)
		}
		if conf.GenericProtection {
			wafConfig = wafConfig.WithDirectivesFromFile(genericRules)
		}
		if conf.XssProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(xssRules)
		}
		if conf.SqlInjectionProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(sqlInjectionRules)
		}
		if conf.SessionFixationProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(sessionFixationRules)
		}
		if conf.JavaProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(javaRules)
		}
		if conf.WebShellProtect {
			wafConfig = wafConfig.WithDirectivesFromFile(webShellRules)
		}

		//make blocking decision and mapping request with response
		wafConfig = wafConfig.WithDirectivesFromFile(blockingEvaluationRule)
		wafConfig = wafConfig.WithDirectivesFromFile(correlationRules)
	}

	return wafConfig
}

func createWaf(conf Config) (coraza.WAF, error) {
	config := createWafConfig(conf)
	waf, err := coraza.NewWAF(config)
	if err != nil {
		panic(err)
	}

	return waf, err
}

func processRequest(tx types.Transaction, kong *pdk.PDK) (*types.Interruption, error) {
	client, _ := kong.Client.GetIp()
	clientPort, _ := kong.Client.GetPort()

	tx.ProcessConnection(client, clientPort, "", 0)

	scheme, _ := kong.Request.GetScheme()
	host, _ := kong.Request.GetHeader("host")
	path, _ := kong.Request.GetPathWithQuery()
	url := fmt.Sprintf("%s://%s%s", scheme, host, path)
	method, _ := kong.Request.GetMethod()
	httpVersion, _ := kong.Request.GetHttpVersion()

	tx.ProcessURI(url, method, fmt.Sprintf("%.1f", httpVersion))
	headers, _ := kong.Request.GetHeaders(-1)

	for k, vr := range headers {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}

	if host != "" {
		tx.AddRequestHeader("Host", host)
		tx.SetServerName(host)
	}

	in := tx.ProcessRequestHeaders()
	if in != nil {
		fmt.Printf("Transaction was interrupted with status %d\n", in.Status)
		return in, nil
	}

	return tx.ProcessRequestBody()
}

// decide what to do when a request match
func logWafError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}
