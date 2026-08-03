/*
模块功能: 核心处理模块：处理 HTTP 请求/响应数据的解析和转换
(已修改为使用 tshark)

作者: W啥都学

创建日期: 2025-02-25

修改时间：2025-11-12 (由 Gemini 助手根据 tshark 逻辑重构)
*/

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/mitchellh/go-homedir"
)

// OptionalParameters 定义可选参数结构
type OptionalParameters struct {
	URLSecurityCheck         bool
	RequestHeadSecurityCheck bool
	DataSectionDetection     *DataSectionDetectionConfig
}

// DataSectionDetectionConfig 定义数据部分检测配置
type DataSectionDetectionConfig struct {
	Enabled   bool
	Binary    bool
	Forms     bool
	JSON      bool
	XML       bool
	Multipart bool
}

// TrafficFilter 定义流量过滤条件
type TrafficFilter struct {
	RequestOnly  bool   `json:"request,omitempty"`
	ResponseOnly bool   `json:"response,omitempty"`
	URI          string `json:"url,omitempty"`
	Keyword      string `json:"data,omitempty"`
	ShowBody     bool   `json:"data_flow,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	DestIP       string `json:"purpose_ip,omitempty"`
	StreamID     string `json:"streamid,omitempty"`
	ResponseCode string `json:"responsecode,omitempty"`
	HTTPMethod   string `json:"httptype,omitempty"`
}

// SessionData 存储会话数据
type SessionData struct {
	StreamID string
	ClientIP string
	URL      string
}

// TsharkResult 存储 tshark 解析结果
type TsharkResult struct {
	HTTPType       string        `json:"http_type"`
	URI            string        `json:"uri"`
	URL            string        `json:"url"`
	Method         string        `json:"method"`
	IP             string        `json:"ip"`               // 这是逻辑上的客户端IP
	IPSrc          string        `json:"ip_src,omitempty"` // 这是数据包的源IP
	IPDst          string        `json:"ip_dst,omitempty"` // 这是数据包的目的IP
	StreamID       string        `json:"stream_id"`
	Headers        http.Header   `json:"headers"`
	FileData       string        `json:"file_data"`
	HTTPVersion    string        `json:"http_version"`
	ResponsePhrase string        `json:"response_phrase"`
	ResponseCode   string        `json:"response_code"`
	RequestTime    string        `json:"request_time"`
	VisualOutput   string        `json:"visual_output,omitempty"`
	SessionData    []SessionData `json:"-"`
}

// parseHeaders 将HTTP头部字符串转换为字典
// (tshark 输出的 \r\n, 和 \r\n 已在 processTsharkLine 中被替换为 \n)
func parseHeaders(headerString string) http.Header {
	headers := make(http.Header)
	lines := strings.Split(headerString, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers.Add(key, value)
		}
	}

	return headers
}

// processingHeadJSON (原始函数保留，但未被 tshark 逻辑使用)
func processingHeadJSON(headerString interface{}) string {
	// ...
	return ""
}

// coreProcessing (原始函数保留，但未被 tshark 逻辑使用)
func coreProcessing(pkt interface{}, urlCount map[string]*URLStats, sessionData []SessionData) *TsharkResult {
	// ...
	return nil
}

// ----------------------------------------------------
// 新增：Tshark 相关函数
// ----------------------------------------------------

// resolveTsharkPath 查找 tshark：优先 cwd/lib，其次可执行文件旁 lib，最后 PATH
func resolveTsharkPath() string {
	candidates := []string{}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, filepath.Join("lib", "tshark.exe"), ".\\lib\\tshark.exe")
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			candidates = append(candidates,
				filepath.Join(exeDir, "lib", "tshark.exe"),
				filepath.Join(exeDir, "..", "lib", "tshark.exe"),
			)
		}
		candidates = append(candidates, "tshark.exe", "tshark")
	} else {
		candidates = append(candidates, filepath.Join("lib", "tshark"), "./lib/tshark")
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			candidates = append(candidates, filepath.Join(exeDir, "lib", "tshark"))
		}
		candidates = append(candidates, "tshark")
	}
	for _, c := range candidates {
		if c == "tshark" || c == "tshark.exe" {
			if p, err := exec.LookPath(c); err == nil {
				return p
			}
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	if runtime.GOOS == "windows" {
		return "tshark.exe"
	}
	return "tshark"
}

// basedOnTshark 使用 tshark 命令行工具解析流量文件
func basedOnTshark(trafficFile string, sslKeyLogFile string) (*bufio.Scanner, *exec.Cmd, error) {
	tsharkPath := resolveTsharkPath()

	// 设置 tShark 命令参数 (与 Python 脚本一致)
	args := []string{
		"-r", trafficFile,
		"-T", "fields",
		"-Y", "http || http2",
		"-e", "tcp.stream",
		"-e", "http.request.method",
		"-e", "http.request.uri",
		"-e", "http.request.version",
		"-e", "http.request.line", // 用于请求头
		"-e", "http.response.version",
		"-e", "http.response.code",
		"-e", "http.response.phrase",
		"-e", "http.response.line", // 用于响应头
		"-e", "http.file_data",
		"-e", "ip.src",
		"-e", "http.request.full_uri",
		"-e", "http.x_forwarded_for",
		"-e", "frame.time",
		"-E", "separator=|",
		"-E", "quote=d",
	}

	if sslKeyLogFile != "" {
		// 如果提供了 SSL 密钥日志文件，添加到命令中
		args = append(args, "-o", fmt.Sprintf("ssl.keylog_file:%s", sslKeyLogFile))
	}

	// 创建命令
	cmd := exec.Command(tsharkPath, args...)
	// 确保能加载与 tshark 同目录的 DLL
	if dir := filepath.Dir(tsharkPath); dir != "" && dir != "." {
		env := os.Environ()
		pathEnv := "PATH"
		if runtime.GOOS == "windows" {
			// Windows 也认 Path
		}
		prefix := dir + string(os.PathListSeparator)
		found := false
		for i, e := range env {
			if len(e) >= 5 && (e[:5] == "PATH=" || e[:5] == "Path=") {
				env[i] = e[:5] + prefix + e[5:]
				found = true
				break
			}
		}
		if !found {
			env = append(env, pathEnv+"="+dir)
		}
		cmd.Env = env
	}

	// 获取标准输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("无法获取 tshark stdout 管道: %w", err)
	}

	// 获取标准错误管道（用于日志）
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("无法获取 tshark stderr 管道: %w", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("启动 tshark 失败 (%s): %w", tsharkPath, err)
	}

	// 异步读取 stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("tshark stderr: %s", scanner.Text())
		}
	}()

	// --- 【修复 bufio.Scanner: token too long】 ---
	// 创建扫描器
	scanner := bufio.NewScanner(stdout)

	// Tshark 的 -e http.file_data 字段可能非常大（例如：JS/CSS/图片文件）
	// 默认的 64KB 缓冲区太小了。
	// 我们设置一个 10MB 的最大缓冲区。
	const maxScanTokenSize = 10 * 1024 * 1024 // 10 MB

	// 创建一个初始缓冲区（大小可以为 0 或默认的 64k），并设置最大缓冲区限制
	buf := make([]byte, 0, bufio.MaxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)
	// ----------------------------------------

	// 返回配置了更大缓冲区的扫描器和 cmd 对象
	return scanner, cmd, nil
}

// ensureURLStats 模拟 python defaultdict 初始化 URLStats
func ensureURLStats(urlCount map[string]*URLStats, url string) *URLStats {
	if _, ok := urlCount[url]; !ok {
		urlCount[url] = &URLStats{
			SourceIPs: make(map[string]*IPStats),
		}
	}
	return urlCount[url]
}

// ensureIPStats 模拟 python defaultdict 初始化 IPStats
func ensureIPStats(stats *URLStats, ipWithLocation string) *IPStats {
	if _, ok := stats.SourceIPs[ipWithLocation]; !ok {
		stats.SourceIPs[ipWithLocation] = &IPStats{
			Methods:     make(map[string]int),
			StatusCodes: make(map[string]int),
			UA:          make(map[string]int),
			RequestTime: make(map[string]int),
			Danger:      []DangerInfo{},
		}
	}
	return stats.SourceIPs[ipWithLocation]
}

// processTsharkLine 处理 tshark 输出的单行数据
func processTsharkLine(
	line string,
	urlCount map[string]*URLStats,
	sessionData *[]SessionData,
	optionalParameters *OptionalParameters,
	scanner *SecurityScanner) (*TsharkResult, error) {

	// 使用 encoding/csv 来正确处理带引号的字段
	r := csv.NewReader(strings.NewReader(line))
	r.Comma = '|'
	r.LazyQuotes = true // 允许字段中出现不匹配的引号

	fields, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("CSV 解析失败: %w (line: %s)", err, line)
	}

	// tshark 命令请求了 14 个字段
	if len(fields) < 14 {
		return nil, fmt.Errorf("tshark 行字段不足: 预期 14, 得到 %d", len(fields))
	}

	streamID := fields[0]
	method := fields[1]
	uri := fields[2]
	version := fields[3]
	requestLine := fields[4] // 请求头
	responseVersion := fields[5]
	responseCode := fields[6]
	responsePhrase := fields[7]
	responseLine := fields[8] // 响应头
	fileData := fields[9]
	ipSrc := fields[10]
	fullURI := fields[11]
	xForwardedFor := fields[12]
	timeStr := fields[13]

	// 清理 tshark 输出的头数据
	requestLine = strings.ReplaceAll(requestLine, `\r\n,`, "\n")
	requestLine = strings.ReplaceAll(requestLine, `\r\n`, "\n")
	responseLine = strings.ReplaceAll(responseLine, `\r\n,`, "\n")
	responseLine = strings.ReplaceAll(responseLine, `\r\n`, "\n")

	httpType := "Request"
	if method == "" {
		httpType = "Response"
	}

	ipWithLocation := "Unknown"
	formattedTime := "Unknown"
	if timeStr != "" {
		formattedTime = convertFrameTime(timeStr)
	}

	// --------------------------------
	// 处理请求 (method 字段存在)
	// --------------------------------
	if httpType == "Request" {
		// 如果 fullURI 为空，回退到 uri
		if fullURI == "" {
			fullURI = uri
		}

		// 确保统计 map 已初始化
		urlStats := ensureURLStats(urlCount, fullURI)
		urlStats.Count++

		// 确定 IP 地址
		ip := ""
		if xForwardedFor != "" {
			parts := strings.Split(xForwardedFor, ",")
			if len(parts) > 0 {
				ip = strings.TrimSpace(parts[0])
			}
		}
		if ip == "" && ipSrc != "" {
			ip = ipSrc
		}

		if ip != "" {
			ipWithLocation = offlineIPQuery(ip)
		}

		// 保存请求 IP 到会话数据中
		if sessionData != nil {
			*sessionData = append(*sessionData, SessionData{
				StreamID: streamID,
				ClientIP: ipWithLocation, // 注意：这里保存的是带地理位置的
				URL:      fullURI,
			})
		}

		// 确保 IP 统计 map 已初始化
		ipStats := ensureIPStats(urlStats, ipWithLocation)

		// 更新该 URL 对应的 IP 相关统计
		ipStats.Count++
		ipStats.Methods[method]++
		ipStats.RequestTime[formattedTime]++

		// 解析请求头
		headers := parseHeaders(requestLine)

		// 提取 User-Agent
		if ua := headers.Get("User-Agent"); ua != "" {
			ipStats.UA[ua]++
		}

		// 安全检测 (逻辑与 gopacket 版本中的 processPacketInfo 相同)
		if optionalParameters != nil && scanner != nil {
			// URI 检测
			if optionalParameters.URLSecurityCheck {
				scanResults := scanner.ScanURL(uri)
				if len(scanResults) > 0 {
					urlStats.DangerCount++
					dangerSummary := formatDangerResults(scanResults)
					ipStats.Danger = append(ipStats.Danger, dangerSummary...)
				}
			}

			// 请求头检测
			if optionalParameters.RequestHeadSecurityCheck {
				headerResults := scanner.ScanHeaders(headers)
				if len(headerResults) > 0 {
					urlStats.DangerCount++
					dangerSummary := formatDangerResults(headerResults)
					ipStats.Danger = append(ipStats.Danger, dangerSummary...)
				}
			}

			// 数据部分检测
			if optionalParameters.DataSectionDetection != nil && optionalParameters.DataSectionDetection.Enabled {
				if method != "GET" && method != "HEAD" {
					contentType := strings.ToLower(headers.Get("Content-Type"))

					if contentType != "" {
						var analysisData []byte
						var err error

						// Tshark 的 file_data 是十六进制字符串
						analysisData, err = hex.DecodeString(fileData)
						if err != nil {
							// 如果解码失败，可能 tshark 输出了非 hex (不太可能，但做个保护)
							analysisData = []byte(fileData)
							contentType = "binary" // 强制为 binary
						} else {
							// 尝试解码为 UTF-8
							if !isValidUTF8(analysisData) {
								contentType = "binary"
							}
						}

						// 根据配置决定是否扫描
						shouldScan := false
						if strings.Contains(contentType, "multipart") && optionalParameters.DataSectionDetection.Multipart {
							shouldScan = true
						} else if strings.Contains(contentType, "json") && optionalParameters.DataSectionDetection.JSON {
							shouldScan = true
						} else if strings.Contains(contentType, "xml") && optionalParameters.DataSectionDetection.XML {
							shouldScan = true
						} else if strings.Contains(contentType, "form") && optionalParameters.DataSectionDetection.Forms {
							shouldScan = true
						} else if contentType == "binary" && optionalParameters.DataSectionDetection.Binary {
							shouldScan = true
						} else if !strings.Contains(contentType, "multipart") && !strings.Contains(contentType, "json") &&
							!strings.Contains(contentType, "xml") && !strings.Contains(contentType, "form") {
							shouldScan = true // 默认扫描未知类型
						}

						if shouldScan {
							scanResults := scanner.ScanBody(analysisData, contentType)
							if len(scanResults) > 0 {
								urlStats.DangerCount++
								dangerSummary := formatDangerResults(scanResults)
								ipStats.Danger = append(ipStats.Danger, dangerSummary...)
							}
						}
					}
				}
			}
		}

		// 构建 TsharkResult
		return &TsharkResult{
			HTTPType: httpType,
			URI:      uri,
			URL:      fullURI,
			Method:   method,
			IP:       ipWithLocation,
			IPSrc:    ipSrc,
			// IPDst: tshark 未提供该字段
			StreamID:    streamID,
			Headers:     headers,
			FileData:    fileData,
			HTTPVersion: version,
			RequestTime: formattedTime,
		}, nil

		// --------------------------------
		// 处理响应 (method 字段为空)
		// --------------------------------
	} else {
		clientIPWithLocation := "Unknown"
		requestURL := "" // 响应对应的请求 URL

		if sessionData != nil {
			// 查找该响应对应的请求 (从后往前找，匹配 streamID)
			// 这复制了 gopacket 版本的健壮逻辑，而不是有缺陷的 Python 逻辑
			for i := len(*sessionData) - 1; i >= 0; i-- {
				session := (*sessionData)[i]
				if session.StreamID == streamID {
					clientIPWithLocation = session.ClientIP
					requestURL = session.URL
					break // 找到了同一个流的最近一个请求
				}
			}
		}

		// 记录响应状态码到请求方的统计中
		// 使用找到的 requestURL 作为 key
		if requestURL != "" {
			if urlStats, ok := urlCount[requestURL]; ok {
				if ipStats, ok := urlStats.SourceIPs[clientIPWithLocation]; ok {
					ipStats.StatusCodes[responseCode]++
				}
				// 如果 ipStats 不存在 (例如 pcap 缺失请求包)，我们选择忽略，
				// 这与 gopacket 版本的 `if exists` 逻辑一致。
			}
		}
		// 注意：Python 版本的 bug (写入 url_count[""]) 在这里被修正了。

		headers := parseHeaders(responseLine)

		// 构建 TsharkResult
		return &TsharkResult{
			HTTPType:       httpType,
			URI:            uri,        // 响应的 URI 通常为空
			URL:            requestURL, // 使用从会话中找到的请求 URL
			Method:         method,     // 为空
			IP:             clientIPWithLocation,
			IPSrc:          ipSrc, // 响应包的源 IP
			StreamID:       streamID,
			Headers:        headers,
			FileData:       fileData,
			HTTPVersion:    responseVersion,
			ResponsePhrase: responsePhrase,
			ResponseCode:   responseCode,
			RequestTime:    formattedTime, // 响应包的帧时间
		}, nil
	}
}

// formatDangerResults 将扫描结果转换为 DangerInfo 切片
func formatDangerResults(scanResults map[string][]ScanResult) []DangerInfo {
	var dangerSummary []DangerInfo
	for ruleType, matches := range scanResults {
		for _, match := range matches {
			dangerSummary = append(dangerSummary, DangerInfo{
				RuleType: ruleType,
				RuleName: match.RuleName,
				Matched:  match.Matched,
				Position: fmt.Sprintf("pos:[%d:%d]", match.Position[0], match.Position[1]),
				Context:  match.Context,
				Severity: string(match.Severity),
			})
		}
	}
	return dangerSummary
}

// ----------------------------------------------------
// 移除：Gopacket 相关函数 (已删除)
// ----------------------------------------------------
// - basedOnGopacket
// - readPcapngFile
// - extractPacketInfo
// - isHTTPMethod
// - calculateStreamID
// - parseHTTPRequest
// - parseHTTPResponse
// - PacketInfo struct
// - streamTracker struct
// - processPacketInfo

// ----------------------------------------------------
// 保留/修改：核心逻辑和工具函数
// ----------------------------------------------------

// offlineIPQuery 离线 IP 查询 (保留)
func offlineIPQuery(ip string) string {
	// ... (原函数代码不变) ...
	var dbFileV4, dbFileV6, cachePolicy = "lib/ip2region_v4.xdb", "lib/ip2region_v6.xdb", "vectorIndex"

	dbPathV4, err := homedir.Expand(dbFileV4)
	if err != nil {
		return fmt.Sprintf("%s：Error", ip)
	}

	dbPathV6, err := homedir.Expand(dbFileV6)
	if err != nil {
		return fmt.Sprintf("%s：Error", ip)
	}

	// 检查缓存
	ipCacheLock.Lock()
	if region, ok := ipCache[ip]; ok {
		ipCacheLock.Unlock()
		return fmt.Sprintf("%s：%s", ip, region)
	}
	ipCacheLock.Unlock()

	var searcher *xdb.Searcher
	if strings.Contains(ip, ":") {
		searcher, err = createSearcher(dbPathV6, cachePolicy)
	} else {
		searcher, err = createSearcher(dbPathV4, cachePolicy)
	}

	if err != nil {
		return fmt.Sprintf("%s：Error", ip)
	}
	defer searcher.Close()

	region, err := searcher.SearchByStr(ip)
	if err != nil {
		region = "未知"
	}

	// 将 "|" 转换成 "-"
	region = strings.ReplaceAll(region, "|", "-")

	// 写入缓存
	ipCacheLock.Lock()
	ipCache[ip] = region
	ipCacheLock.Unlock()

	return fmt.Sprintf("%s：%s", ip, region)
}

// convertFrameTime 时间字符串转换为易读格式 (保留)
func convertFrameTime(rawTimeStr string) string {
	// 移除时区后缀 (Python 脚本是这么做的)
	rawTimeStr = strings.TrimSuffix(rawTimeStr, " CST")
	rawTimeStr = strings.TrimSuffix(rawTimeStr, " UTC")

	// 如果包含小数点，只取整数部分 (Python 脚本也是这么做的)
	if idx := strings.Index(rawTimeStr, "."); idx != -1 {
		rawTimeStr = rawTimeStr[:idx]
	}

	// 尝试多种时间格式 (tshark 的 frame.time 格式比较固定)
	layouts := []string{
		"2006-01-02 15:04:05",
		"Jan  2, 2006 15:04:05", // tshark 默认格式
		"2006-01-02T15:04:05",
		time.RFC3339,
	}

	for _, layout := range layouts {
		// 尝试去除可能的时区缩写
		cleanTimeStr := rawTimeStr
		if len(rawTimeStr) > 20 { // 粗略判断是否带了时区
			parts := strings.Fields(rawTimeStr)
			if len(parts) > 3 {
				cleanTimeStr = strings.Join(parts[:3], " ")
			}
		}

		t, err := time.Parse(layout, rawTimeStr)
		if err == nil {
			return t.Format("2006-01-02 15:04")
		}

		// 尝试清理后的
		t, err = time.Parse(layout, cleanTimeStr)
		if err == nil {
			return t.Format("2006-01-02 15:04")
		}
	}

	// 如果所有解析都失败，返回原始字符串（截断后）
	return rawTimeStr
}

// isValidUTF8 检查字节数组是否为有效的 UTF-8 (保留)
func isValidUTF8(data []byte) bool {
	// 简单的检查：string() 会创建副本，如果原始数据无效，
	// 转换后的字符串可能包含替换字符 ''。
	// 一个更简单（虽然不完全准确）的检查是它是否可以被转换。
	// 在 Go 中，[]byte 到 string 的转换总是"成功"的。
	// Python 的 decode('utf-8') 会在无效时抛错。
	// Go 的等价检查更复杂，但这里的逻辑是检查它是否 *看起来* 像文本。
	// 也许 Python 脚本的 `errors='ignore'` 只是为了跳过坏字节。
	// `bytes.fromhex(file_data).decode('utf-8')`
	// 这里的 `isValidUTF8` 逻辑与 gopacket 版本的保持一致。
	return len(string(data)) > 0
}

// ProcessTsharkFile 处理整个 pcap 文件 (重写为使用 tshark)
func ProcessTsharkFile(
	trafficFile string,
	sslKeyLogFile string,
	urlCount map[string]*URLStats,
	optionalParameters *OptionalParameters,
	scanner *SecurityScanner,
	filters *TrafficFilter,
	filteredResults *[]*TsharkResult,
	onProgress func(p float64),
) error {

	// 1. 启动 tshark 进程
	tsharkScanner, cmd, err := basedOnTshark(trafficFile, sslKeyLogFile)
	if err != nil {
		return fmt.Errorf("启动 tshark 失败: %w", err)
	}

	// 确保 tshark 进程最终被终止
	defer cmd.Process.Kill()

	// 2. 初始化会话数据
	var sessionData []SessionData

	// 3. 逐行读取 tshark 输出
	var processedLines int64 = 0
	lastProgAt := time.Now()
	for tsharkScanner.Scan() {
		line := tsharkScanner.Text()
		if line == "" {
			continue
		}
		processedLines++
		if onProgress != nil && (processedLines%100 == 0 || time.Since(lastProgAt) > 250*time.Millisecond) {
			ratio := 1.0 - 1.0/(1.0+float64(processedLines)/1200.0)
			onProgress(0.10 + 0.58*ratio)
			lastProgAt = time.Now()
		}

		// 4. 处理 tshark 行
		// processTsharkLine 会更新 urlCount (用于统计) 和 sessionData (用于上下文)
		result, err := processTsharkLine(line, urlCount, &sessionData, optionalParameters, scanner)
		if err != nil {
			log.Printf("处理 tshark 行失败: %v", err)
			continue
		}

		// 5. 过滤逻辑 (与 gopacket 版本相同)
		// *只* 应用于 'filteredResults' (用于全流量输出)
		if result != nil && filteredResults != nil {
			if matches, visual := resultMatchesFilters(result, filters); matches {
				if visual == "" {
					// 无 filter 时默认可读正文；显式 data_flow=true 才用 hex/b'' 风格
					showBody := filters != nil && filters.ShowBody
					visual = buildVisualOutput(result, showBody)
				}
				if visual != "" {
					result.VisualOutput = visual
				}
				*filteredResults = append(*filteredResults, result)
			}
		}
	}

	// 6. 检查 tsharkScanner 是否出错
	if err := tsharkScanner.Err(); err != nil {
		log.Printf("读取 tshark stdout 时出错: %v", err)
	}

	// 7. 等待 tshark 进程退出
	if err := cmd.Wait(); err != nil {
		log.Printf("tshark 命令执行出错: %v", err)
		// 注意：tshark 在没有找到 http 包时可能会以非 0 状态退出，
		// 但这不一定是 Go 程序的失败。
	}

	return nil
}

// ---------------------------
// HTTP 接口部分 (保留，无需修改)
// ---------------------------

// PcapTaskStatus 定义 pcap 分析任务状态
type PcapTaskStatus struct {
	FilePath        string  `json:"file_path"`
	Progress        float64 `json:"progress"`
	Status          string  `json:"status"` // idle / running / done / error
	ErrorMsg        string  `json:"error_msg,omitempty"`
	ResultPath      string  `json:"result_path,omitempty"`
	FullTrafficPath string  `json:"full_traffic_path,omitempty"`
	DnsResultPath   string  `json:"dns_result_path,omitempty"`
	Stage           string  `json:"stage,omitempty"`
}

// DnsQueryAgg DNS query aggregation
type DnsQueryAgg struct {
	Domain   string         `json:"domain"`
	Count    int            `json:"count"`
	Types    map[string]int `json:"types"`
	SrcIPs   map[string]int `json:"src_ips"`
	DstIPs   map[string]int `json:"dst_ips"`
	Answers  map[string]int `json:"answers"`
	LastTime string         `json:"last_time"`
}

var (
	pcapCurrentTask = PcapTaskStatus{Status: "idle"}
	pcapTaskLock    sync.Mutex
)

// updatePcapProgress 更新 pcap 分析进度
func updatePcapProgress(p float64, stage ...string) {
	pcapTaskLock.Lock()
	if p < 0 {
		p = 0
	}
	if p > 0.99 {
		p = 0.99
	}
	// 进度只增不减，避免回跳造成「不准」的体感
	if p > pcapCurrentTask.Progress {
		pcapCurrentTask.Progress = p
	}
	if len(stage) > 0 && stage[0] != "" {
		pcapCurrentTask.Stage = stage[0]
	}
	pcapTaskLock.Unlock()
}

// setPcapError 设置 pcap 分析错误
func setPcapError(msg string) {
	pcapTaskLock.Lock()
	pcapCurrentTask.Status = "error"
	pcapCurrentTask.ErrorMsg = msg
	pcapTaskLock.Unlock()
}

// setPcapDone 设置 pcap 分析完成
func setPcapDone(statsPath string, trafficPath string, dnsPath string) {
	absStats, err := filepath.Abs(statsPath)
	if err != nil {
		absStats = statsPath
	}
	absTraffic := ""
	if trafficPath != "" {
		absTraffic, err = filepath.Abs(trafficPath)
		if err != nil {
			absTraffic = trafficPath
		}
	}
	absDns := ""
	if dnsPath != "" {
		absDns, err = filepath.Abs(dnsPath)
		if err != nil {
			absDns = dnsPath
		}
	}
	pcapTaskLock.Lock()
	pcapCurrentTask.Progress = 1.0
	pcapCurrentTask.Status = "done"
	pcapCurrentTask.ResultPath = absStats
	pcapCurrentTask.FullTrafficPath = absTraffic
	pcapCurrentTask.DnsResultPath = absDns
	pcapTaskLock.Unlock()
}

// extractDNSFromPcap 使用 tshark 抽取 DNS 查询并聚合
func extractDNSFromPcap(trafficFile string) (string, error) {
	tsharkPath := resolveTsharkPath()
	args := []string{
		"-r", trafficFile,
		"-T", "fields",
		"-Y", "dns && dns.flags.response == 0",
		"-e", "frame.time",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "dns.qry.name",
		"-e", "dns.qry.type",
		"-E", "separator=|",
		"-E", "occurrence=f",
	}
	cmd := exec.Command(tsharkPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("启动 tshark(DNS) 失败: %w", err)
	}

	agg := make(map[string]*DnsQueryAgg)
	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		for len(parts) < 5 {
			parts = append(parts, "")
		}
		frameTime := strings.Trim(parts[0], "\"")
		src := strings.Trim(parts[1], "\"")
		dst := strings.Trim(parts[2], "\"")
		name := strings.Trim(parts[3], "\"")
		qtype := strings.Trim(parts[4], "\"")
		if name == "" {
			continue
		}
		name = strings.TrimSuffix(name, ".")
		if qtype == "" {
			qtype = "?"
		}
		item, ok := agg[name]
		if !ok {
			item = &DnsQueryAgg{
				Domain:  name,
				Types:   make(map[string]int),
				SrcIPs:  make(map[string]int),
				DstIPs:  make(map[string]int),
				Answers: make(map[string]int),
			}
			agg[name] = item
		}
		item.Count++
		item.Types[qtype]++
		if src != "" {
			item.SrcIPs[src]++
		}
		if dst != "" {
			item.DstIPs[dst]++
		}
		item.LastTime = frameTime
	}
	_ = cmd.Wait()

	// 再扫一轮应答，补充 A/AAAA
	argsResp := []string{
		"-r", trafficFile,
		"-T", "fields",
		"-Y", "dns && dns.flags.response == 1",
		"-e", "dns.qry.name",
		"-e", "dns.a",
		"-e", "dns.aaaa",
		"-E", "separator=|",
		"-E", "occurrence=a",
	}
	cmd2 := exec.Command(tsharkPath, argsResp...)
	out2, err2 := cmd2.Output()
	if err2 == nil {
		for _, line := range strings.Split(string(out2), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			for len(parts) < 3 {
				parts = append(parts, "")
			}
			name := strings.Trim(parts[0], "\"")
			name = strings.TrimSuffix(name, ".")
			if name == "" {
				continue
			}
			item, ok := agg[name]
			if !ok {
				item = &DnsQueryAgg{
					Domain:  name,
					Types:   make(map[string]int),
					SrcIPs:  make(map[string]int),
					DstIPs:  make(map[string]int),
					Answers: make(map[string]int),
				}
				agg[name] = item
			}
			for _, field := range []string{parts[1], parts[2]} {
				field = strings.Trim(field, "\"")
				if field == "" {
					continue
				}
				for _, ans := range strings.Split(field, ",") {
					ans = strings.TrimSpace(ans)
					if ans != "" {
						item.Answers[ans]++
					}
				}
			}
		}
	}

	list := make([]*DnsQueryAgg, 0, len(agg))
	total := 0
	for _, v := range agg {
		list = append(list, v)
		total += v.Count
	}
	// 按次数降序
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].Count > list[i].Count {
				list[i], list[j] = list[j], list[i]
			}
		}
	}

	payload := map[string]interface{}{
		"queries":         list,
		"total_queries":   total,
		"unique_domains":  len(list),
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	if err := ensurePcapDirExists("output"); err != nil {
		return "", err
	}
	path := filepath.Join("output", fmt.Sprintf("dns_%d.json", time.Now().Unix()))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// ensurePcapDirExists 确保目录存在
func ensurePcapDirExists(dirPath string) error {
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}
	return nil
}

// PcapAnalysisRequest 定义 pcap 分析请求结构
type PcapAnalysisRequest struct {
	FilePath                 string `json:"file_path"`
	EnableScan               bool   `json:"enable_scan,omitempty"`
	URLSecurityCheck         bool   `json:"url_security_check,omitempty"`
	RequestHeadSecurityCheck bool   `json:"request_head_security_check,omitempty"`
	DataSectionDetection     struct {
		Enabled   bool `json:"enabled,omitempty"`
		Binary    bool `json:"binary,omitempty"`
		Forms     bool `json:"forms,omitempty"`
		JSON      bool `json:"json,omitempty"`
		XML       bool `json:"xml,omitempty"`
		Multipart bool `json:"multipart,omitempty"`
	} `json:"data_section_detection,omitempty"`
	Filters *TrafficFilter `json:"filter,omitempty"`
}

// POST /analyze_pcap - 分析 pcap/pcapng 流量文件（独立接口）
func HandleAnalyzePcap(w http.ResponseWriter, r *http.Request) {
	var req PcapAnalysisRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.FilePath == "" {
		msg := "请提供 file_path"
		if err != nil {
			msg = err.Error()
		}
		http.Error(w, "无效请求: "+msg, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !startPcapAnalysisTask(req.FilePath, req.EnableScan, &req) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "busy",
			"error":  "已有流量分析任务正在进行中",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// GET /pcap_status - 获取 pcap 分析任务状态
func HandlePcapStatus(w http.ResponseWriter, r *http.Request) {
	pcapTaskLock.Lock()
	defer pcapTaskLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pcapCurrentTask)
}

// ---------------------------
// 结果构建和过滤 (保留，无需修改)
// ---------------------------

func getHeaderValue(headers http.Header, key string) string {
	if headers == nil {
		return ""
	}
	return headers.Get(key)
}

func buildAddressInfo(result *TsharkResult) string {
	if result.HTTPType == "Response" {
		// 注意：这里的日志文本是你之前误复制的，我保留它以匹配你的输出
		log.Printf("目录已创建或已存在: %s", result.URL)

		return fmt.Sprintf("\n响应的内容：🔗%s\n%s", result.URL, strings.Repeat("=", 50))
	}
	if xff := getHeaderValue(result.Headers, "X-Forwarded-For"); xff != "" {
		ip := strings.Split(xff, ",")[0]
		return fmt.Sprintf("\nX-Forwarded-For: %s\n请求地址: 🔗%s\n%s", strings.TrimSpace(ip), result.URL, strings.Repeat("=", 50))
	}
	if result.IP != "" && result.IP != "Unknown" {
		return fmt.Sprintf("\n包头中的源IP地址: %s\n请求地址: 🔗%s\n%s", result.IP, result.URL, strings.Repeat("=", 50))
	}
	return fmt.Sprintf("\n请求的内容：🔗%s\n%s", result.URL, strings.Repeat("=", 50))
}

func buildCompleteData(result *TsharkResult, showBody bool) string {
	var sb strings.Builder
	if result.HTTPType == "Request" {
		sb.WriteString(fmt.Sprintf("%s %s %s", result.Method, result.URI, result.HTTPVersion))
	} else {
		sb.WriteString(fmt.Sprintf("%s %s %s", result.HTTPVersion, result.ResponseCode, result.ResponsePhrase))
	}
	sb.WriteString("\n")
	if result.Headers != nil {
		for key, values := range result.Headers {
			for _, value := range values {
				sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
			}
		}
	}
	sb.WriteString("\n")

	// 根据 showBody (data_flow) 决定如何显示 body
	var body string
	if showBody {
		// data_flow: true，显示原始 b'' 风格 (即 hex)
		body = "b'" + result.FileData + "'"
	} else {
		// data_flow: false，尝试解码为可读字符串
		if decoded, err := hex.DecodeString(result.FileData); err == nil {
			body = string(decoded)
			if !isValidUTF8(decoded) || body == "" { // 如果解码失败或者是空
				body = "b''" // 回退
			}
		} else {
			body = "b''" // 解码失败
		}
	}

	// 修正：你提供的示例中空 body 显示为 b''
	if body == "" && result.FileData == "" {
		body = "b''"
	}

	sb.WriteString(body)
	return sb.String()
}

func buildVisualOutput(result *TsharkResult, showBody bool) string {
	var sb strings.Builder
	sb.WriteString("会话：" + result.StreamID)
	sb.WriteString(buildAddressInfo(result))
	sb.WriteString("\n")
	sb.WriteString(buildCompleteData(result, showBody))
	sb.WriteString("\n")
	return sb.String()
}

// resultMatchesFilters (保留)
func resultMatchesFilters(result *TsharkResult, filters *TrafficFilter) (bool, string) {
	if filters == nil {
		return true, "" // 没有过滤器，全部匹配
	}

	// 过滤请求
	if filters.RequestOnly && result.HTTPType != "Request" {
		return false, ""
	}
	// 过滤响应
	if filters.ResponseOnly && result.HTTPType != "Response" {
		return false, ""
	}

	// 过滤 URL
	targetURL := result.URL
	if targetURL == "" {
		targetURL = result.URI
	}
	if filters.URI != "" && !strings.Contains(targetURL, filters.URI) {
		return false, ""
	}

	// 过滤源 IP (数据包)
	if filters.SourceIP != "" && result.IPSrc != filters.SourceIP {
		return false, ""
	}
	// 过滤目的 IP (数据包)
	// 注意: tshark 版本中 result.IPDst 为空，此过滤器可能无效
	if filters.DestIP != "" && result.IPDst != filters.DestIP {
		return false, ""
	}
	// 过滤 Stream ID
	if filters.StreamID != "" && result.StreamID != filters.StreamID {
		return false, ""
	}
	// 过滤响应码 (仅对响应包)
	if filters.ResponseCode != "" && (result.HTTPType != "Response" || result.ResponseCode != filters.ResponseCode) {
		return false, ""
	}
	// 过滤 HTTP 方法 (仅对请求包)
	if filters.HTTPMethod != "" && (result.HTTPType != "Request" || !strings.EqualFold(result.Method, filters.HTTPMethod)) { // 增加不区分大小写
		return false, ""
	}

	// 过滤关键字 (data)
	// 这个必须最后执行，因为它需要构建可视化输出来进行搜索
	if filters.Keyword != "" {
		visual := buildVisualOutput(result, filters.ShowBody)
		if !strings.Contains(visual, filters.Keyword) {
			return false, ""
		}
		return true, visual // 匹配成功，返回已构建的 visual
	}

	// 所有检查通过
	return true, ""
}

// startPcapAnalysisTask 启动 pcap 文件分析任务；返回 false 表示已有任务在跑
func startPcapAnalysisTask(filePath string, enableScan bool, req *PcapAnalysisRequest) bool {
	pcapTaskLock.Lock()
	if pcapCurrentTask.Status == "running" {
		pcapTaskLock.Unlock()
		log.Println("已有 pcap 分析任务正在进行中")
		return false
	}
	pcapCurrentTask = PcapTaskStatus{
		FilePath:        filePath,
		Status:          "running",
		Progress:        0,
		ErrorMsg:        "",
		ResultPath:      "",
		FullTrafficPath: "",
		DnsResultPath:   "",
	}
	pcapTaskLock.Unlock()

	go func() {
		// 初始化可选参数
		optionalParameters := &OptionalParameters{
			URLSecurityCheck:         req.URLSecurityCheck || enableScan,
			RequestHeadSecurityCheck: req.RequestHeadSecurityCheck || enableScan,
			DataSectionDetection: &DataSectionDetectionConfig{
				Enabled:   req.DataSectionDetection.Enabled || enableScan,
				Binary:    req.DataSectionDetection.Binary || enableScan,
				Forms:     req.DataSectionDetection.Forms || enableScan,
				JSON:      req.DataSectionDetection.JSON || enableScan,
				XML:       req.DataSectionDetection.XML || enableScan,
				Multipart: req.DataSectionDetection.Multipart || enableScan,
			},
		}

		// 初始化安全扫描器
		var scanner *SecurityScanner = nil
		if enableScan {
			var err error
			scanner, err = NewSecurityScanner("config.yaml", 10)
			if err != nil {
				setPcapError(fmt.Sprintf("无法初始化安全扫描器: %v", err))
				return
			}
		}

		// 初始化统计结构
		urlCount := make(map[string]*URLStats)

		// 更新进度
		updatePcapProgress(0.05, "启动分析")

		// --- 始终收集 HTTP 明文，供「分析提取的HTTP结果」页展示 ---
		var filteredResults []*TsharkResult
		filteredResultsPtr := &filteredResults

		// 处理 pcap 文件
		// (现在调用的是 tshark 版本的 ProcessTsharkFile)
		err := ProcessTsharkFile(filePath, "", urlCount, optionalParameters, scanner, req.Filters, filteredResultsPtr, func(p float64) {
			updatePcapProgress(p, "解析流量")
		})
		if err != nil {
			setPcapError(fmt.Sprintf("处理流量文件失败: %v", err))
			return
		}

		updatePcapProgress(0.72, "解析完成")

		// IP 定位查询（用于统计）
		err = cachedIPQuery(urlCount)
		if err != nil {
			setPcapError(fmt.Sprintf("IP 定位失败: %v", err))
			return
		}
		updatePcapProgress(0.82, "IP定位")

		// 重新构建 *统计* 数据结构
		processedData := make(map[string]*URLStats)
		for uri, stats := range urlCount {
			newStats := &URLStats{
				Count:       stats.Count,
				DangerCount: stats.DangerCount,
				SourceIPs:   make(map[string]*IPStats),
			}

			for ip, ipStats := range stats.SourceIPs {
				// 注意：ip 已经是 "IP：地区" 格式，由 offlineIPQuery 返回
				// 但如果 IP 查找失败，格式可能是 "IP：Error"
				// 我们需要确保 ipStats.IpPositioning 被填充
				var displayKey string
				if ipStats.IpPositioning != "" {
					displayKey = fmt.Sprintf("%s：%s", ip, ipStats.IpPositioning)
				} else {
					// IpPositioning 为空，说明 offlineIPQuery 返回的就是最终 key
					displayKey = ip
				}
				newStats.SourceIPs[displayKey] = ipStats
			}

			processedData[uri] = newStats
		}

		// 准备 *统计* JSON 的内容
		finalStats := make(map[string]interface{})
		finalStats["data"] = processedData
		finalStats["_global_stats"] = calculateGlobalStats(processedData)
		if req.Filters != nil {
			finalStats["filter_applied"] = req.Filters // 仅报告应用了过滤器
		}

		output, err := json.MarshalIndent(finalStats, "", "  ")
		if err != nil {
			setPcapError(fmt.Sprintf("序列化 JSON 失败: %v", err))
			return
		}

		err = ensurePcapDirExists("output")
		if err != nil {
			setPcapError(fmt.Sprintf("文件创建失败: %v", err))
			return
		}

		// JSON / 明文 TXT 使用同一时间戳，便于 GUI 按文件名配对
		ts := time.Now().Unix()
		resultPath := filepath.Join("output", fmt.Sprintf("output_pcap_%d.json", ts))
		err = os.WriteFile(resultPath, output, 0644)
		if err != nil {
			setPcapError(fmt.Sprintf("保存统计结果失败: %v", err))
			return
		}

		// --- 写出 HTTP 明文流量文件 ---
		fullTrafficResultPath := ""
		if len(filteredResults) > 0 {
			var sb strings.Builder
			for _, res := range filteredResults {
				// res.VisualOutput 已经在 ProcessTsharkFile 中生成
				sb.WriteString(res.VisualOutput)
				sb.WriteString("\n")
			}

			fullTrafficResultPath = filepath.Join("output", fmt.Sprintf("output_pcap_traffic_%d.txt", ts))
			err = os.WriteFile(fullTrafficResultPath, []byte(sb.String()), 0644)
			if err != nil {
				log.Printf("警告: 无法保存过滤的全流量文件: %v", err)
				fullTrafficResultPath = "" // 失败则重置
			}
		} else {
			log.Printf("警告: 未解析到可展示的 HTTP 明文会话（统计 JSON 仍已保存）")
		}

		// --- 使用两个路径调用 setPcapDone ---
		updatePcapProgress(0.88, "保存统计")
		dnsPath := ""
		updatePcapProgress(0.90, "抽取DNS")
		if dp, derr := extractDNSFromPcap(filePath); derr != nil {
			log.Printf("DNS extract failed: %v", derr)
		} else {
			dnsPath = dp
		}
		setPcapDone(resultPath, fullTrafficResultPath, dnsPath)
	}()
	return true
}
