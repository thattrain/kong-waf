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
	secAuditLogPathRegex  = `(?m)(^(?<indent>\s*)?(?<key>SecAuditLog\s+)(?<value>.*)$)`
)

func createWafConfig(conf Config, kong *pdk.PDK) coraza.WAFConfig {

	corazaRules := loadFile(corazaConf)
	secEngineRegex := regexp.MustCompile(secRuleEngineRegex)
	if conf.DetectionMode {
		kong.Log.Debug("Creat WAF instance with SecRuleEngine DetectionOnly")
		corazaRules = secEngineRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", secRuleEngineValueDetectOnly))
	} else if conf.EnforceMode {
		kong.Log.Info("Creat WAF instance with SecRuleEngine On")
		corazaRules = secEngineRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", secRuleEngineEnforce))
	} else {
		kong.Log.Info("Creat WAF instance with SecRuleEngine Off")
		corazaRules = secEngineRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", secRuleEngineOff))
	}

	if conf.SecDebugLogPath != "" {
		err := createFile(conf.SecDebugLogPath)
		if err != nil {
			kong.Log.Err(fmt.Printf("Error creating SecDebugLog file: %v", err))
		} else {
			secDebugLogPathRegex := regexp.MustCompile(secDebugLogPathRegex)
			corazaRules = secDebugLogPathRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", conf.SecDebugLogPath))
		}
	}

	if conf.SecAuditLogPath != "" {
		err := createFile(conf.SecAuditLogPath)
		if err != nil {
			kong.Log.Err(fmt.Printf("Error creating SecAuditLog file: %v", err))
		} else {
			secAuditLogPathRegex := regexp.MustCompile(secAuditLogPathRegex)
			corazaRules = secAuditLogPathRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%s", conf.SecAuditLogPath))
		}
	}

	if conf.LogLevel != 0 {
		secDebugLogLevelRegex := regexp.MustCompile(secDebugLogLevelRegex)
		corazaRules = secDebugLogLevelRegex.ReplaceAllString(corazaRules, fmt.Sprintf("${index}${key}%d", conf.LogLevel))
	}

	// order of directives must be in correct order in compile time
	wafConfig := coraza.NewWAFConfig().
		WithRootFS(embedFS).
		WithDirectives(corazaRules).
		WithDirectivesFromFile(crsConf).
		WithErrorCallback(logWafError)

	if conf.EnableAll {
		kong.Log.Info("Create WAF instance with all rules enable")
		wafConfig = wafConfig.WithDirectivesFromFile(coreRules)
	} else {
		// order of directives must be in correct order in compile time
		// init core rule set
		wafConfig = wafConfig.WithDirectivesFromFile(csrInitRule)
		if conf.ScannerDetection {
			kong.Log.Info("Create WAF instance with scanner detection rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(scannerDetectionRules)
		}
		if conf.MultipartProtect {
			kong.Log.Info("Create WAF instance with multipart protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(multipartRules)
		}
		if conf.PhpProtect {
			kong.Log.Info("Create WAF instance with PHP protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(phpRules)
		}
		if conf.RceProtect {
			kong.Log.Info("Create WAF instance with RCE protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(rceRules)
		}
		if conf.GenericProtection {
			kong.Log.Info("Create WAF instance with generic protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(genericRules)
		}
		if conf.XssProtect {
			kong.Log.Info("Create WAF instance with XSS protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(xssRules)
		}
		if conf.SqlInjectionProtect {
			kong.Log.Info("Create WAF instance with SQL Injection protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(sqlInjectionRules)
		}
		if conf.SessionFixationProtect {
			kong.Log.Info("Create WAF instance with session fixation protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(sessionFixationRules)
		}
		if conf.JavaProtect {
			kong.Log.Info("Create WAF instance with Java protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(javaRules)
		}
		if conf.WebShellProtect {
			kong.Log.Info("Create WAF instance with web shell protect rules enable")
			wafConfig = wafConfig.WithDirectivesFromFile(webShellRules)
		}

		//make blocking decision and mapping request with response
		wafConfig = wafConfig.WithDirectivesFromFile(blockingEvaluationRule)
		wafConfig = wafConfig.WithDirectivesFromFile(correlationRules)
	}

	return wafConfig
}

func createWaf(conf Config, kong *pdk.PDK) (coraza.WAF, error) {
	config := createWafConfig(conf, kong)
	waf, err := coraza.NewWAF(config)
	if err != nil {
		panic(err)
	}

	return waf, err
}

func processRequest(tx types.Transaction, kong *pdk.PDK) (*types.Interruption, error) {

	realIp, err := kong.Request.GetHeader("x-forwarded-for")
	clientPort, _ := kong.Client.GetPort()
	if err != nil || realIp == "" {
		client, _ := kong.Client.GetIp()
		tx.ProcessConnection(client, clientPort, "", 0)
	} else {
		kong.Log.Info(fmt.Printf("Client ip address: %s", realIp))
		tx.ProcessConnection(realIp, clientPort, "", 0)
	}

	scheme, _ := kong.Request.GetScheme()
	host, _ := kong.Request.GetHeader("host")
	path, _ := kong.Request.GetPathWithQuery()
	url := fmt.Sprintf("%s://%s%s", scheme, host, path)
	method, _ := kong.Request.GetMethod()
	httpVersion, _ := kong.Request.GetHttpVersion()

	tx.ProcessURI(url, method, fmt.Sprintf("%.1f", httpVersion))
	headers, _ := kong.Request.GetHeaders(-1)

	for key, value := range headers {
		for _, v := range value {
			tx.AddRequestHeader(key, v)
		}
	}

	if host != "" {
		tx.AddRequestHeader("Host", host)
		tx.SetServerName(host)
	}

	headerInterruption := tx.ProcessRequestHeaders()
	if headerInterruption != nil {
		kong.Log.Warn("Transaction was interrupted with status %d\n", headerInterruption.Status)
		return headerInterruption, nil
	}

	return tx.ProcessRequestBody()
}

// decide what to do when a request match
func logWafError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("RULE_MATCHED|%s|%s\n", error.Rule().Severity(), msg)
}
