package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/go-homedir"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"gopkg.in/yaml.v3"
)

// --- 用于配置和统计的结构体 ---

// Config 结构体用于存储从 config.yaml 文件中加载的配置信息
type ConfigLog struct {
	LogFormats      map[string]string         `yaml:"log_formats"` // 日志格式的映射，键是格式名称，值是正则表达式
	ParsersRaw      map[string]interface{}    `yaml:"parsers"`     // 从 YAML 中原始解析出的解析器
	Parsers         map[string]Parser         `yaml:"-"`           // 转换和整理后的解析器
	CompiledFormats map[string]*regexp.Regexp // 编译后的日志格式正则表达式
	CompiledParsers map[string]*regexp.Regexp // 编译后的解析器正则表达式
}

// Parser 结构体定义了单个解析器的结构
type Parser struct {
	Pattern string `yaml:"pattern"` // 用于解析的正则表达式模式
}

// URLStats 结构体用于存储每个 URL 的统计信息
type URLStats struct {
	Count       int                 `json:"count"`        // URL 被请求的总次数
	DangerCount int                 `json:"danger_count"` // URL 相关的危险请求次数
	SourceIPs   map[string]*IPStats `json:"source_ips"`   // 源 IP 地址及其统计信息的映射
}

// IPStats 结构体用于存储每个 IP 地址的详细统计信息
type IPStats struct {
	Count         int            `json:"count"`         // 该 IP 的请求总数
	Methods       map[string]int `json:"methods"`       // 使用的 HTTP 方法及其次数
	StatusCodes   map[string]int `json:"status_codes"`  // 返回的状态码及其次数
	IpPositioning string         `json:"ipPositioning"` // 返回的状态码及其次数
	UA            map[string]int `json:"UA"`            // User-Agent 及其次数
	RequestTime   map[string]int `json:"request_time"`  // 请求时间（格式化后）及其次数
	Danger        []DangerInfo   `json:"danger"`        // 检测到的危险信息列表
	// haproxy 特有字段
	Sizes    map[string]int `json:"sizes,omitempty"`    // 响应大小
	Frontend map[string]int `json:"frontend,omitempty"` // 前端名称
	Backend  map[string]int `json:"backend,omitempty"`  // 后端名称
}

// DangerInfo 结构体用于存储检测到的安全风险详情
type DangerInfo struct {
	RuleType string `json:"rule_type"` // 规则类型
	RuleName string `json:"rule_name"` // 规则名称
	Matched  string `json:"matched"`   // 匹配到的内容
	Position string `json:"position"`  // 匹配位置
	Context  string `json:"context"`   // 上下文
	Severity string `json:"severity"`  // 严重性
}

// GlobalStats 结构体用于存储全局的统计信息
type GlobalStats struct {
	RequestTotal           int `json:"request_total"`            // 总请求数
	DangerTotal            int `json:"danger_total"`             // 总危险请求数
	TotalUniqueIPs         int `json:"total_unique_ips"`         // 独立 IP 总数
	TotalUniqueURIs        int `json:"total_unique_uris"`        // 独立 URI 总数
	TotalUniqueStatusCodes int `json:"total_unique_status_code"` // 独立状态码总数
}

// ParsedLineInfo 结构体用于在解析协程和聚合协程之间传递数据
type ParsedLineInfo struct {
	IP            string
	Path          string
	Method        string
	StatusCode    string
	UserAgent     string
	FormattedTime string
	Dangers       []DangerInfo
}

// --- Global Variables ---
// --- 全局变量 ---

var (
	ipCache     = make(map[string]string) // IP 地址查询结果的缓存
	ipCacheLock = &sync.Mutex{}           // 用于保护 ipCache 的互斥锁
	ipSearcher  *xdb.Searcher             // ip2region 的查询器
)

// --- Initialization ---
// --- 初始化 ---

// loadConfig 函数从指定的路径加载并解析 YAML 配置文件
func loadConfig(configPath string) (*ConfigLog, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var conf ConfigLog
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, fmt.Errorf("解析 YAML 文件失败: %w", err)
	}

	// 处理灵活的 Parser 格式（可以是字符串或 map）
	conf.Parsers = make(map[string]Parser)
	for name, p := range conf.ParsersRaw {
		if patternStr, ok := p.(string); ok {
			// 如果是字符串，直接转换
			conf.Parsers[name] = Parser{Pattern: patternStr}
		} else if parserMap, ok := p.(map[string]interface{}); ok {
			// 如果是 map，提取 pattern 字段
			if pattern, ok := parserMap["pattern"].(string); ok {
				conf.Parsers[name] = Parser{Pattern: pattern}
			}
		}
	}

	// 编译日志格式的正则表达式
	conf.CompiledFormats = make(map[string]*regexp.Regexp)
	for name, pattern := range conf.LogFormats {
		conf.CompiledFormats[name], err = regexp.Compile(pattern)
		if err != nil {
			log.Printf("警告: 编译日志格式正则表达式 '%s' 失败: %v", name, err)
		}
	}

	// 编译解析器的正则表达式
	conf.CompiledParsers = make(map[string]*regexp.Regexp)
	for name, parser := range conf.Parsers {
		conf.CompiledParsers[name], err = regexp.Compile(parser.Pattern)
		if err != nil {
			log.Printf("警告: 编译解析器正则表达式 '%s' 失败: %v", name, err)
		}
	}

	return &conf, nil
}

// --- Helper Functions ---
// --- 辅助函数 ---

// cachedIPQuery 函数查询 IP 地址的地理位置信息，并使用缓存

func cachedIPQuery(urlStats map[string]*URLStats) error {
	var dbFileV4, dbFileV6, cachePolicy = "lib/ip2region_v4.xdb", "lib/ip2region_v6.xdb", "vectorIndex"

	dbPathV4, err := homedir.Expand(dbFileV4)
	if err != nil {
		return fmt.Errorf("xdb文件路径无效 `%s`: %s", dbFileV4, err)
	}
	dbPathV6, err := homedir.Expand(dbFileV6)
	if err != nil {
		return fmt.Errorf("xdb文件路径无效 `%s`: %s", dbFileV6, err)
	}

	searcherV4, err := createSearcher(dbPathV4, cachePolicy)
	if err != nil {
		return fmt.Errorf("创建 IPv4 搜索器失败: %w", err)
	}
	defer searcherV4.Close()

	searcherV6, err := createSearcher(dbPathV6, cachePolicy)
	if err != nil {
		return fmt.Errorf("创建 IPv6 搜索器失败: %w", err)
	}
	defer searcherV6.Close()

	for _, u := range urlStats {
		for ip, stat := range u.SourceIPs {
			if ip == "" {
				continue
			}

			// 检查缓存
			ipCacheLock.Lock()
			if region, ok := ipCache[ip]; ok {
				stat.IpPositioning = region
				ipCacheLock.Unlock()
				continue
			}
			ipCacheLock.Unlock()

			var region string
			// IPv6 与 IPv4 简单区分
			if strings.Contains(ip, ":") {
				region, err = searcherV6.SearchByStr(ip)
			} else {
				region, err = searcherV4.SearchByStr(ip)
			}
			if err != nil {
				region = "未知"
			}

			// --- 关键：把 “|” 转换成 “-” ---
			region = strings.ReplaceAll(region, "|", "-")

			// 写入缓存与统计结构
			ipCacheLock.Lock()
			ipCache[ip] = region
			ipCacheLock.Unlock()

			stat.IpPositioning = region
		}
	}

	return nil
}

func createSearcher(dbPath string, cachePolicy string) (*xdb.Searcher, error) {
	handle, err := os.OpenFile(dbPath, os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open xdb file `%s`: %w", dbPath, err)
	}

	defer handle.Close()

	// verify the xdb file
	// @Note: do NOT call it every time you create a searcher since this will slow down the search response.
	// @see the util.Verify function for details.
	err = xdb.Verify(handle)
	if err != nil {
		return nil, fmt.Errorf("xdb verify: %w", err)
	}

	// auto-detect the ip version from the xdb header
	header, err := xdb.LoadHeader(handle)
	if err != nil {
		return nil, fmt.Errorf("failed to load header from `%s`: %s", dbPath, err)
	}

	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("failed to detect IP version from `%s`: %s", dbPath, err)
	}

	switch cachePolicy {
	case "nil", "file":
		return xdb.NewWithFileOnly(version, dbPath)
	case "vectorIndex":
		vIndex, err := xdb.LoadVectorIndexFromFile(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load vector index from `%s`: %w", dbPath, err)
		}

		return xdb.NewWithVectorIndex(version, dbPath, vIndex)
	case "content":
		cBuff, err := xdb.LoadContentFromFile(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load content from '%s': %w", dbPath, err)
		}

		return xdb.NewWithBuffer(version, cBuff)
	default:
		return nil, fmt.Errorf("invalid cache policy `%s`, options: file/vectorIndex/content", cachePolicy)
	}
}

// formatTimeStr 函数将不同格式的时间字符串统一格式化
func formatTimeStr(timestr string) string {
	layouts := []string{
		"02/Jan/2006:15:04:05 -0700", // Nginx, Apache 格式
		"2006-01-02 15:04:05-0700",   // 自定义格式
		time.RFC3339,                 // RFC3339 格式
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, timestr)
		if err == nil {
			return t.Format("2006-01-02 15:04")
		}
	}
	// 兼容 IIS 格式 "YYYY-MM-DD HH:MM:SS"
	t, err := time.Parse("2006-01-02 15:04:05", timestr)
	if err == nil {
		return t.Format("2006-01-02 15:04")
	}

	return timestr // 如果所有解析都失败，返回原始字符串
}

// getRegexGroup 函数从正则表达式的匹配结果中按名称获取捕获组的值
func getRegexGroup(match []string, names []string, groupName string) string {
	for i, name := range names {
		if name == groupName {
			if i < len(match) {
				return match[i]
			}
			return ""
		}
	}
	return ""
}

// --- Log Parsing Functions ---
// --- 日志解析函数 ---

// parseAccessLine 函数解析通用的 Web 访问日志行
func parseAccessLine(logLine string, urlCount map[string]*URLStats, conf *ConfigLog, scanner *SecurityScanner) {
	re, ok := conf.CompiledParsers["common_web_log"]
	if !ok {
		return // 如果没有对应的解析器，直接返回
	}
	match := re.FindStringSubmatch(logLine)
	if match == nil {
		//log.Printf("Line did not match common_web_log: %s", logLine)
		return // 如果不匹配，直接返回
	}

	names := re.SubexpNames()
	ip := getRegexGroup(match, names, "ip")
	path := getRegexGroup(match, names, "path")
	method := getRegexGroup(match, names, "method")
	statusCode := getRegexGroup(match, names, "status_code")
	userAgent := getRegexGroup(match, names, "user_agent")
	timeStr := getRegexGroup(match, names, "time")
	formattedTime := formatTimeStr(timeStr)

	// 如果是新的 URL，初始化其统计结构
	if _, exists := urlCount[path]; !exists {
		urlCount[path] = &URLStats{SourceIPs: make(map[string]*IPStats)}
	}
	urlCount[path].Count++

	ipInfo := ip
	// 如果是新的 IP，初始化其统计结构
	if _, exists := urlCount[path].SourceIPs[ipInfo]; !exists {
		urlCount[path].SourceIPs[ipInfo] = &IPStats{
			Methods:     make(map[string]int),
			StatusCodes: make(map[string]int),
			UA:          make(map[string]int),
			RequestTime: make(map[string]int),
			Danger:      []DangerInfo{},
		}
	}

	// 更新 IP 的统计数据
	ipStats := urlCount[path].SourceIPs[ipInfo]
	ipStats.Count++
	ipStats.Methods[method]++
	ipStats.StatusCodes[statusCode]++
	ipStats.UA[userAgent]++
	ipStats.RequestTime[formattedTime]++

	// --- ⬇️ SECURITY SCAN INTEGRATION START ⬇️ ---
	// 此处集成了安全扫描逻辑
	if scanner != nil {
		// 1. 扫描 URL 和 User-Agent
		scanResults := scanner.ScanURL(path)
		headerData := http.Header{}
		headerData.Add("User-Agent", userAgent)
		headerScanResults := scanner.ScanHeaders(headerData)
		mergeResults(scanResults, headerScanResults, "")

		// 2. 如果有发现，则转换并存储
		if len(scanResults) > 0 {
			dangers := formatDangerResults(scanResults)
			if len(dangers) > 0 {
				ipStats.Danger = append(ipStats.Danger, dangers...)
				urlCount[path].DangerCount += len(dangers)
			}
		}
	}
	// --- ⬆️ SECURITY SCAN INTEGRATION END ⬆️ ---
}

// 其他解析函数（如 parse_json_web_log 等）可以遵循类似的模式。
// 为简洁起见，这里只实现了一个主要的。用户可以自行扩展。

// --- Main Processing Logic ---
// --- 主要处理逻辑 ---
// 在文件顶部（与其它 type/var 同级）添加进度回调类型
type ProgressFunc func(p float64)


// getRegexGroupSafe returns named group or empty
func getRegexGroupSafe(match []string, names []string, name string) string {
	return getRegexGroup(match, names, name)
}

var genericIPRe = regexp.MustCompile(`(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})`)
var genericReqRe = regexp.MustCompile(`"(?P<method>[A-Z]{3,10})\s+(?P<path>[^"\s]+)\s+HTTP/[0-9.]+"`)
var genericStatusRe = regexp.MustCompile(`\s(?P<status>\d{3})\s`)
var genericUARe = regexp.MustCompile(`"(?P<ua>[^"]*)"\s*$`)

func parseWithParser(conf *ConfigLog, parserName, logLine string, ipKey, pathKey, methodKey, statusKey, uaKey, timeKey string) *ParsedLineInfo {
	re, ok := conf.CompiledParsers[parserName]
	if !ok || re == nil {
		return nil
	}
	match := re.FindStringSubmatch(logLine)
	if match == nil {
		return nil
	}
	names := re.SubexpNames()
	info := &ParsedLineInfo{
		IP:            getRegexGroup(match, names, ipKey),
		Path:          getRegexGroup(match, names, pathKey),
		Method:        getRegexGroup(match, names, methodKey),
		StatusCode:    getRegexGroup(match, names, statusKey),
		UserAgent:     getRegexGroup(match, names, uaKey),
		FormattedTime: formatTimeStr(getRegexGroup(match, names, timeKey)),
	}
	if info.Path == "" {
		return nil
	}
	if info.IP == "" {
		info.IP = "0.0.0.0"
	}
	if info.Method == "" {
		info.Method = "-"
	}
	if info.StatusCode == "" {
		info.StatusCode = "-"
	}
	return info
}

func parseJSONLogLine(logLine string) *ParsedLineInfo {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(logLine), &data); err != nil {
		return nil
	}
	getStr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := data[k]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
		}
		return ""
	}
	path := getStr("url", "uri", "path", "request_uri", "URL", "URI")
	if path == "" {
		return nil
	}
	ip := getStr("client_ip", "ip", "src_ip", "remote_addr", "sip")
	if ip == "" {
		ip = "0.0.0.0"
	}
	method := getStr("method", "http_method", "Method")
	if method == "" {
		method = "-"
	}
	status := getStr("status_code", "status", "code", "Status")
	if status == "" {
		status = "-"
	}
	ua := getStr("user_agent", "ua", "User-Agent")
	return &ParsedLineInfo{
		IP:            ip,
		Path:          path,
		Method:        method,
		StatusCode:    status,
		UserAgent:     ua,
		FormattedTime: getStr("time", "timestamp", "datetime"),
	}
}

func parseGenericWebLog(logLine string) *ParsedLineInfo {
	req := genericReqRe.FindStringSubmatch(logLine)
	if req == nil {
		return nil
	}
	reqNames := genericReqRe.SubexpNames()
	path := getRegexGroup(req, reqNames, "path")
	method := getRegexGroup(req, reqNames, "method")
	ip := "0.0.0.0"
	if m := genericIPRe.FindStringSubmatch(logLine); m != nil {
		ip = m[1]
	}
	status := "-"
	if m := genericStatusRe.FindStringSubmatch(logLine); m != nil {
		status = m[1]
	}
	ua := ""
	if m := genericUARe.FindStringSubmatch(logLine); m != nil {
		ua = m[1]
	}
	return &ParsedLineInfo{
		IP:         ip,
		Path:       path,
		Method:     method,
		StatusCode: status,
		UserAgent:  ua,
	}
}

// parseAnyLogLine tries typed parser then fallbacks
func parseAnyLogLine(logLine string, logType string, conf *ConfigLog) *ParsedLineInfo {
	var info *ParsedLineInfo
	switch logType {
	case "iis_log":
		info = parseWithParser(conf, "iis_log", logLine, "client_ip", "path", "method", "status_code", "user_agent", "time")
		if info != nil && info.FormattedTime == "" {
			// combine date+time if present
			re := conf.CompiledParsers["iis_log"]
			match := re.FindStringSubmatch(logLine)
			names := re.SubexpNames()
			d := getRegexGroup(match, names, "date")
			t := getRegexGroup(match, names, "time")
			if d != "" && t != "" {
				info.FormattedTime = d + " " + t
			}
		}
	case "haproxy_access":
		info = parseWithParser(conf, "haproxy_access", logLine, "ip", "path", "method", "status_code", "", "timestamp")
	case "json_log":
		info = parseJSONLogLine(logLine)
	case "apache_access", "nginx_access", "tomcat_access_log", "f5_healthcheck", "common_web_log":
		info = parseWithParser(conf, "common_web_log", logLine, "ip", "path", "method", "status_code", "user_agent", "time")
	case "generic_web_log", "unknown":
		// fall through to cascade
	}
	if info != nil {
		return info
	}
	// cascade fallbacks
	if info = parseWithParser(conf, "common_web_log", logLine, "ip", "path", "method", "status_code", "user_agent", "time"); info != nil {
		return info
	}
	if info = parseWithParser(conf, "iis_log", logLine, "client_ip", "path", "method", "status_code", "user_agent", "time"); info != nil {
		return info
	}
	if info = parseWithParser(conf, "haproxy_access", logLine, "ip", "path", "method", "status_code", "", "timestamp"); info != nil {
		return info
	}
	trimmed := strings.TrimSpace(logLine)
	if strings.HasPrefix(trimmed, "{") {
		if info = parseJSONLogLine(trimmed); info != nil {
			return info
		}
	}
	return parseGenericWebLog(logLine)
}


// logWorker 是并发执行的协程，负责解析和扫描
func logWorker(
	wg *sync.WaitGroup,
	lines <-chan string,
	results chan<- ParsedLineInfo,
	conf *ConfigLog,
	scanner *SecurityScanner,
	logType string,
) {
	defer wg.Done()

	for logLine := range lines {
		infoPtr := parseAnyLogLine(logLine, logType, conf)
		if infoPtr == nil {
			continue
		}
		info := *infoPtr

		if scanner != nil {
			allScanResults := scanner.ScanURL(info.Path)
			headerData := http.Header{}
			headerData.Add("User-Agent", info.UserAgent)
			headerScanResults := scanner.ScanHeaders(headerData)
			mergeResults(allScanResults, headerScanResults, "")
			if len(allScanResults) > 0 {
				info.Dangers = formatDangerResults(allScanResults)
			}
		}
		results <- info
	}
}

// resultAggregator
//  是一个单独的协程，负责安全地将结果写入 map
func resultAggregator(
	wg *sync.WaitGroup,
	results <-chan ParsedLineInfo,
	urlCount map[string]*URLStats,
) {
	defer wg.Done()

	for info := range results {
		// 这部分逻辑与您原来 parseAccessLine 的后半部分相同
		if _, exists := urlCount[info.Path]; !exists {
			urlCount[info.Path] = &URLStats{SourceIPs: make(map[string]*IPStats)}
		}
		urlStats := urlCount[info.Path]
		urlStats.Count++

		ipInfo := info.IP
		if _, exists := urlStats.SourceIPs[ipInfo]; !exists {
			urlStats.SourceIPs[ipInfo] = &IPStats{
				Methods:     make(map[string]int),
				StatusCodes: make(map[string]int),
				UA:          make(map[string]int),
				RequestTime: make(map[string]int),
				Danger:      []DangerInfo{},
			}
		}

		ipStats := urlStats.SourceIPs[ipInfo]
		ipStats.Count++
		ipStats.Methods[info.Method]++
		ipStats.StatusCodes[info.StatusCode]++
		ipStats.UA[info.UserAgent]++
		ipStats.RequestTime[info.FormattedTime]++

		if len(info.Dangers) > 0 {
			ipStats.Danger = append(ipStats.Danger, info.Dangers...)
			urlStats.DangerCount += len(info.Dangers) // 累加危险计数
		}
	}
}

// processLogFile 函数处理单个日志文件
// processLogFile 函数使用并发池处理日志文件
func processLogFile(filePath string, conf *ConfigLog, logType string, progress ProgressFunc, scannerUrl *SecurityScanner) (map[string]*URLStats, error) {
	// --- 1. 统计总行数（用于计算百分比）---
	fcount, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	scannerCount := bufio.NewScanner(fcount)
	var totalLines int64 = 0
	for scannerCount.Scan() {
		totalLines++
	}
	_ = scannerCount.Err()
	fcount.Close()

	if totalLines == 0 {
		if progress != nil {
			progress(1.0)
		}
		return make(map[string]*URLStats), nil
	}

	// --- 2. 准备并发处理 ---
	urlCount := make(map[string]*URLStats)

	// linesChannel 用于从生产者（文件读取）发送到消费者（Worker）
	// 缓冲区大小设为 1000，防止生产者因消费者繁忙而阻塞
	linesChannel := make(chan string, 1000)

	// resultsChannel 用于从消费者（Worker）发送到聚合器
	resultsChannel := make(chan ParsedLineInfo, 1000)

	var wgWorkers sync.WaitGroup
	var wgAggregator sync.WaitGroup

	// --- 3. 启动 N 个 Worker 协程 ---
	numWorkers := runtime.NumCPU() // 使用所有可用的 CPU 核心
	log.Printf("启动 %d 个 Worker 协程进行解析和扫描...", numWorkers)
	for i := 0; i < numWorkers; i++ {
		wgWorkers.Add(1)
		go logWorker(&wgWorkers, linesChannel, resultsChannel, conf, scannerUrl, logType)
	}

	// --- 4. 启动 1 个聚合器协程 ---
	wgAggregator.Add(1)
	go resultAggregator(&wgAggregator, resultsChannel, urlCount)

	// --- 5. 开始第二次遍历（生产者） ---
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var processed int64 = 0
	var lastReportPercent int = -1
	const minLinesBetweenReport = 1000

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.ReplaceAll(line, "＂", "\"") // 替换全角引号
		processed++

		if line != "" {
			// 根据日志类型选择是否发送到处理通道
			switch logType {
			case "apache_access", "nginx_access", "tomcat_access_log", "f5_healthcheck", "common_web_log",
				"iis_log", "haproxy_access", "json_log", "generic_web_log", "unknown":
				linesChannel <- line
			default:
				// still try generic pipeline
				linesChannel <- line
			}
		}

		// --- 6. 进度报告（不变） ---
		if processed%minLinesBetweenReport == 0 || int((processed*100)/totalLines) != lastReportPercent {
			curPercent := float64(processed) / float64(totalLines)
			if progress != nil {
				progress(curPercent)
			}
			lastReportPercent = int((processed * 100) / totalLines)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件时出错: %w", err)
	}

	// --- 7. 关闭和等待 ---
	log.Println("文件读取完毕。等待 Worker 完成处理...")
	close(linesChannel) // 1. 生产者完成，关闭 linesChannel
	wgWorkers.Wait()    // 2. 等待所有 Worker 处理完
	log.Println("Worker 处理完毕。等待聚合器完成...")
	close(resultsChannel) // 3. Worker 完成，关闭 resultsChannel
	wgAggregator.Wait()   // 4. 等待聚合器处理完所有结果
	log.Println("聚合器处理完毕。")

	if progress != nil {
		progress(1.0)
	}

	return urlCount, nil
}

// guessLogFormat 函数通过匹配多行来猜测日志格式
func guessLogFormat(filePath string, conf *ConfigLog, maxLines int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "unknown", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	// 读取最多 maxLines 行用于猜测
	for i := 0; i < maxLines && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		line = strings.ReplaceAll(line, "＂", "\"") // 替换全角引号
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return "unknown", nil
	}

	matches := make(map[string]int)
	for name := range conf.CompiledFormats {
		matches[name] = 0
	}

	// 统计每种格式的匹配行数
	for _, line := range lines {
		for name, pattern := range conf.CompiledFormats {
			if pattern.MatchString(line) {
				matches[name]++
			}
		}
	}

	log.Printf("Match counts: %+v\n", matches)

	bestMatch := "unknown"
	maxCount := 0
	// 找到匹配行数最多的格式
	for name, count := range matches {

		if count > maxCount {
			maxCount = count
			bestMatch = name
		}
	}

	// 如果最佳匹配的行数占比超过 50%，则认为猜测成功
	if float64(maxCount)/float64(len(lines)) >= 0.5 {
		return bestMatch, nil
	}

	return "unknown", nil
}

// calculateGlobalStats 函数计算全局统计数据
// calculateGlobalStats 函数计算全局统计数据
func calculateGlobalStats(urlCount map[string]*URLStats) *GlobalStats {
	stats := &GlobalStats{}
	totalIPs := make(map[string]struct{})
	totalURIs := make(map[string]struct{})
	totalStatusCodes := make(map[string]struct{})

	for uri, data := range urlCount {
		stats.RequestTotal += data.Count
		stats.DangerTotal += data.DangerCount // <-- 【新增】累加每个URL的风险计数
		totalURIs[uri] = struct{}{}

		for ip, ipData := range data.SourceIPs {
			totalIPs[ip] = struct{}{}
			for code := range ipData.StatusCodes {
				totalStatusCodes[code] = struct{}{}
			}
		}
	}

	stats.TotalUniqueIPs = len(totalIPs)
	stats.TotalUniqueURIs = len(totalURIs)
	stats.TotalUniqueStatusCodes = len(totalStatusCodes)

	return stats
}

type TaskStatus struct {
	FilePath   string  `json:"file_path"`
	LogType    string  `json:"log_type"`
	Progress   float64 `json:"progress"`
	Status     string  `json:"status"` // idle / running / done / error
	ErrorMsg   string  `json:"error_msg,omitempty"`
	ResultPath string  `json:"result_path,omitempty"`
}

var (
	currentTask = TaskStatus{Status: "idle"}
	taskLock    sync.Mutex
)

// 将处理阶段的进度（0.0-1.0）映射到整体进度区间 [stageStart, stageEnd]
func mapStageProgress(stageStart, stageEnd, stageProgress float64) float64 {
	if stageProgress < 0 {
		stageProgress = 0
	}
	if stageProgress > 1 {
		stageProgress = 1
	}
	return stageStart + (stageEnd-stageStart)*stageProgress
}

func ensureDirExists(dirPath string) error {
	// 使用 MkdirAll 创建目录（包括所有父目录）
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	return nil
}

// ---------------------------
// 启动分析任务
// ---------------------------
// startAnalysis 同步检查忙状态并启动后台任务；返回 false 表示已有任务在跑
func startAnalysis(filePath string, enableScan bool) bool {
	taskLock.Lock()
	if currentTask.Status == "running" {
		taskLock.Unlock()
		log.Println("已有任务正在进行中")
		return false
	}
	currentTask = TaskStatus{
		FilePath:   filePath,
		Status:     "running",
		Progress:   0,
		ErrorMsg:   "",
		ResultPath: "",
		LogType:    "",
	}
	taskLock.Unlock()

	go func() {
		conf, err := loadConfig("config.yaml")
		if err != nil {
			setError(err.Error())
			return
		}

		logType, err := guessLogFormat(filePath, conf, 20)
		if err != nil {
			setError(fmt.Sprintf("无法猜测日志格式: %v", err))
			return
		}
		if logType == "unknown" {
			logType = "generic_web_log"
			log.Println("format unknown, use generic_web_log fallback")
		}
		setLogType(logType)

		progressCallback := func(p float64) {
			overall := mapStageProgress(0.0, 0.95, p)
			updateProgress(overall)
		}

		var scannerUrl *SecurityScanner = nil

		if enableScan {
			log.Println("安全扫描已启用。")
			var err error
			scannerUrl, err = NewSecurityScanner("config.yaml", 10)
			if err != nil {
				setError(fmt.Sprintf("无法初始化安全扫描器: %v", err))
				return
			}
		} else {
			log.Println("安全扫描已禁用。")
		}

		urlCount, err := processLogFile(filePath, conf, logType, progressCallback, scannerUrl)
		if err != nil {
			setError(fmt.Sprintf("处理日志文件失败: %v", err))
			return
		}

		err = cachedIPQuery(urlCount)
		if err != nil {
			setError(fmt.Sprintf("IP 定位失败: %v", err))
			return
		}
		updateProgress(0.95)

		processedData := make(map[string]*URLStats)
		for uri, stats := range urlCount {
			newStats := &URLStats{
				Count:       stats.Count,
				DangerCount: stats.DangerCount,
				SourceIPs:   make(map[string]*IPStats),
			}

			for ip, ipStats := range stats.SourceIPs {
				newKey := fmt.Sprintf("%s：%s", ip, ipStats.IpPositioning)
				newStats.SourceIPs[newKey] = ipStats
			}

			processedData[uri] = newStats
		}

		finalStats := make(map[string]interface{})
		finalStats["data"] = processedData
		finalStats["_global_stats"] = calculateGlobalStats(urlCount)

		output, err := json.MarshalIndent(finalStats, "", "  ")
		if err != nil {
			setError(fmt.Sprintf("序列化 JSON 失败: %v", err))
			return
		}
		err = ensureDirExists("output")
		if err != nil {
			setError(fmt.Sprintf("文件创建失败: %v", err))
			return
		}
		resultPath := filepath.Join("output", fmt.Sprintf("output_%d.json", time.Now().Unix()))
		err = os.WriteFile(resultPath, output, 0644)
		if err != nil {
			setError(fmt.Sprintf("保存结果失败: %v", err))
			return
		}

		setDone(resultPath)
	}()
	return true
}

// ---------------------------
// 状态更新工具函数
// ---------------------------
func updateProgress(p float64) {
	taskLock.Lock()
	currentTask.Progress = p
	taskLock.Unlock()
}

func setLogType(t string) {
	taskLock.Lock()
	currentTask.LogType = t
	taskLock.Unlock()
}

func setError(msg string) {
	taskLock.Lock()
	currentTask.Status = "error"
	currentTask.ErrorMsg = msg
	taskLock.Unlock()
}

func setDone(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	taskLock.Lock()
	currentTask.Progress = 1.0
	currentTask.Status = "done"
	currentTask.ResultPath = absPath
	taskLock.Unlock()
}

// ---------------------------
// HTTP 接口部分
// ---------------------------

// POST /analyze
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	type Req struct {
		FilePath   string `json:"file_path"`
		EnableScan bool   `json:"enable_scan,omitempty"`
	}
	var req Req
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.FilePath == "" {
		http.Error(w, "无效请求: 请提供 file_path", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !startAnalysis(req.FilePath, req.EnableScan) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "busy",
			"error":  "已有日志分析任务正在进行中",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// GET /status
func handleStatus(w http.ResponseWriter, r *http.Request) {
	taskLock.Lock()
	defer taskLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentTask)
}

// ---------------------------
// 主入口与上传处理
// ---------------------------

// resolveAndChdirBase 定位含 config.yaml 的工作根目录并 chdir
func resolveAndChdirBase() (string, error) {
	exePath, err := os.Executable()
	exeDir := "."
	if err == nil {
		exeDir = filepath.Dir(exePath)
		if resolved, err2 := filepath.EvalSymlinks(exePath); err2 == nil {
			exeDir = filepath.Dir(resolved)
		}
	}

	cwd, _ := os.Getwd()
	candidates := []string{
		cwd,
		filepath.Join(exeDir, ".."),
		exeDir,
	}

	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(abs, "config.yaml")); err == nil {
			if err := os.Chdir(abs); err != nil {
				return "", fmt.Errorf("切换工作目录失败 %s: %w", abs, err)
			}
			return abs, nil
		}
	}

	return cwd, nil
}

func init() {
	// 目录创建推迟到 main 中 resolveAndChdirBase 之后
}

// 处理日志文件上传
func handleUploadLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "获取文件失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	enableScan := r.FormValue("enable_scan") == "true"

	savePath := filepath.Join("uploads", header.Filename)
	out, err := os.Create(savePath)
	if err != nil {
		http.Error(w, "创建文件失败", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)

	w.Header().Set("Content-Type", "application/json")
	if !startAnalysis(savePath, enableScan) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "busy",
			"error":  "已有日志分析任务正在进行中",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// 处理 PCAP 文件上传（走独立 PCAP 状态机）
func handleUploadPcap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "获取文件失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	savePath := filepath.Join("uploads", header.Filename)
	out, err := os.Create(savePath)
	if err != nil {
		http.Error(w, "保存文件失败", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)

	req := &PcapAnalysisRequest{
		FilePath:   savePath,
		EnableScan: r.FormValue("enable_scan") == "true",
	}
	req.URLSecurityCheck = r.FormValue("url_security_check") == "true"
	req.DataSectionDetection.Enabled = req.URLSecurityCheck

	w.Header().Set("Content-Type", "application/json")
	if !startPcapAnalysisTask(req.FilePath, req.EnableScan, req) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "busy",
			"error":  "已有流量分析任务正在进行中",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func main() {
	portFlag := flag.Int("port", 10632, "服务器端口号")
	flag.Parse()

	port := *portFlag
	if envPort := os.Getenv("GO_SERVER_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && *portFlag == 10632 {
			port = p
		}
	}

	baseDir, err := resolveAndChdirBase()
	if err != nil {
		log.Fatalf("初始化工作目录失败: %v", err)
	}
	os.MkdirAll("uploads", 0755)
	os.MkdirAll("output", 0755)
	log.Printf("工作目录: %s", baseDir)

	http.Handle("/", http.FileServer(http.Dir(".")))
	http.Handle("/output/", http.StripPrefix("/output/", http.FileServer(http.Dir("output"))))

	http.HandleFunc("/upload_log", handleUploadLog)
	http.HandleFunc("/upload_pcap", handleUploadPcap)
	http.HandleFunc("/analyze", handleAnalyze)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/log_status", handleStatus)
	http.HandleFunc("/analyze_pcap", HandleAnalyzePcap)
	http.HandleFunc("/pcap_status", HandlePcapStatus)

	// 默认仅本机；公开 Web 网关时务必 127.0.0.1，勿把 Go 端口暴露到公网
	bindHost := strings.TrimSpace(os.Getenv("TRAFFICEYE_LISTEN"))
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindHost, port))
	if err != nil {
		log.Fatalf("无法启动服务器: %v", err)
	}

	actualPort := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("PORT:%d\n", actualPort)
	fmt.Printf("安全分析平台已启动: http://127.0.0.1:%d\n", actualPort)

	log.Fatal(http.Serve(listener, nil))
}
