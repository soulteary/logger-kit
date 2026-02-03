# Logger Kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/logger-kit.svg)](https://pkg.go.dev/github.com/soulteary/logger-kit)
[![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/logger-kit)](https://goreportcard.com/report/github.com/soulteary/logger-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/logger-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/logger-kit)

[English](README.md)

基于 [zerolog](https://github.com/rs/zerolog) 的 Go 应用结构化日志工具包。提供动态日志级别管理、基于上下文的日志记录，以及用于运行时日志级别调整的 HTTP 端点。

## 功能特性

- **zerolog 封装**：支持 JSON 和控制台输出格式的结构化日志
- **动态日志级别**：线程安全的日志级别管理，支持运行时调整
- **HTTP 端点**：RESTful API 用于在运行时获取/设置日志级别
- **上下文日志**：请求 ID、追踪 ID、Span ID 和用户 ID 的传播
- **中间件**：支持 net/http 和 Fiber 的请求日志中间件
- **格式选项**：JSON 和人类可读的控制台输出

## 安全说明

- **Level 端点**：生产环境中必须设置 `AllowedIPs` 或 `RequireAuth`，且不要将端点暴露到公网。若部署在反向代理后，请设置 `TrustedProxies` 为代理 IP。
- **Query/Body 日志**：默认会记录 URL 查询参数；可通过 `SensitiveQueryParams`（默认会脱敏 password、token 等常见参数）避免泄露敏感信息。敏感接口请勿开启 `IncludeBody`。
- 详见 [SECURITY.md](SECURITY.md) 及漏洞报告方式。

## 安装

```bash
go get github.com/soulteary/logger-kit
```

## 快速开始

### 基本用法

```go
package main

import (
    "github.com/soulteary/logger-kit"
)

func main() {
    // 使用默认日志器
    logger.Info().Msg("应用程序已启动")
    
    // 带字段
    logger.Info().
        Str("user", "john").
        Int("attempt", 1).
        Msg("登录尝试")
    
    // 带错误
    logger.Error().
        Err(err).
        Str("operation", "database_query").
        Msg("查询失败")
}
```

### 自定义日志器

```go
package main

import (
    "os"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    // 创建自定义日志器
    log := logger.New(logger.Config{
        Level:          logger.DebugLevel,
        Output:         os.Stdout,
        Format:         logger.FormatJSON,
        ServiceName:    "my-service",
        ServiceVersion: "1.0.0",
        CallerEnabled:  true,
    })
    
    log.Info().Msg("自定义日志器已就绪")
}
```

### 动态日志级别

```go
package main

import (
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    // 获取当前级别
    currentLevel := log.GetLevel()
    
    // 在运行时更改级别
    log.SetLevel(logger.DebugLevel)
    
    // 注册级别更改回调
    unregister := log.LevelManager().OnChange(func(old, new logger.Level) {
        fmt.Printf("日志级别从 %s 更改为 %s\n", old, new)
    })
    defer unregister()
}
```

### 日志级别管理 HTTP 端点

```go
package main

import (
    "net/http"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    // 注册日志级别端点
    mux := http.NewServeMux()
    logger.RegisterLevelEndpoint(mux, "/log/level", logger.LevelHandlerConfig{
        Logger: log,
        AllowedIPs: []string{"127.0.0.1"},
    })
    
    http.ListenAndServe(":8080", mux)
}

// GET /log/level - 获取当前日志级别
// PUT /log/level - 设置日志级别（请求体：{"level": "debug"}）
```

**安全（Level 端点）：** 生产环境必须设置 `AllowedIPs` 或 `RequireAuth`，仅允许受信任的调用方修改日志级别；不要将端点暴露到公网。若在反向代理后，请设置 `TrustedProxies` 为代理 IP，以便正确识别客户端 IP。详见 [SECURITY.md](SECURITY.md)。

### 请求日志中间件

#### net/http

```go
package main

import (
    "net/http"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    middleware := logger.Middleware(logger.MiddlewareConfig{
        Logger:           log,
        SkipPaths:        []string{"/health", "/metrics"},
        IncludeRequestID: true,
        IncludeLatency:   true,
        IncludeHeaders:   false, // 设置为 true 以记录请求头
    })
    
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 从上下文访问日志器
        l := logger.LoggerFromRequest(r)
        l.Info().Msg("处理请求")
        
        // 访问请求 ID
        requestID := logger.RequestIDFromRequest(r)
        
        w.Write([]byte("OK"))
    })
    
    http.ListenAndServe(":8080", middleware(handler))
}
```

#### Fiber

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    app := fiber.New()
    
    app.Use(logger.FiberMiddleware(logger.MiddlewareConfig{
        Logger:           log,
        SkipPaths:        []string{"/health"},
        IncludeRequestID: true,
    }))
    
    app.Get("/", func(c *fiber.Ctx) error {
        // 从 Fiber 上下文访问日志器
        l := logger.LoggerFromFiberCtx(c)
        l.Info().Msg("处理请求")
        
        return c.SendString("OK")
    })
    
    // 注册日志级别端点
    logger.RegisterLevelEndpointFiber(app, "/log/level", logger.LevelHandlerConfig{
        Logger: log,
    })
    
    app.Listen(":3000")
}
```

### 基于上下文的日志记录

```go
package main

import (
    "context"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.NewDefault()
    
    // 创建带有日志器和 ID 的上下文
    ctx := context.Background()
    ctx = logger.ContextWithLogger(ctx, log)
    ctx = logger.ContextWithRequestID(ctx, "req-123")
    ctx = logger.ContextWithTraceID(ctx, "trace-456")
    ctx = logger.ContextWithUserID(ctx, "user-001")
    
    // 使用上下文记录日志 - 自动包含所有 ID
    l := logger.Ctx(ctx)
    l.Info().Msg("处理请求")
    // 输出：{"level":"info","request_id":"req-123","trace_id":"trace-456","user_id":"user-001","message":"处理请求"}
}
```

### 控制台格式（人类可读）

```go
package main

import (
    "os"
    
    "github.com/soulteary/logger-kit"
)

func main() {
    log := logger.New(logger.Config{
        Level:  logger.InfoLevel,
        Output: os.Stdout,
        Format: logger.FormatConsole, // 人类可读格式
    })
    
    log.Info().Str("user", "john").Msg("用户已登录")
    // 输出：3:04PM INF 用户已登录 user=john
}
```

### 从环境变量解析日志级别

```go
package main

import (
    "github.com/soulteary/logger-kit"
)

func main() {
    // 从 LOG_LEVEL 环境变量读取日志级别
    // 如果未设置或无效，则回退到 InfoLevel
    level := logger.ParseLevelFromEnv("LOG_LEVEL", logger.InfoLevel)
    
    log := logger.New(logger.Config{
        Level: level,
    })
    
    log.Info().Msg("日志器已初始化")
}
```

## API 参考

### 日志级别

| 级别 | 描述 |
|------|------|
| `TraceLevel` | 最详细的级别 |
| `DebugLevel` | 调试消息 |
| `InfoLevel` | 信息性消息（默认） |
| `WarnLevel` | 警告消息 |
| `ErrorLevel` | 错误消息 |
| `FatalLevel` | 致命消息（调用 os.Exit(1)） |
| `PanicLevel` | 恐慌消息（触发 panic） |
| `Disabled` | 禁用日志 |

### 配置选项

```go
type Config struct {
    Level                Level     // 最低日志级别（默认：InfoLevel）
    Output               io.Writer // 日志输出（默认：os.Stderr）
    Format               Format    // 输出格式：FormatJSON 或 FormatConsole
    TimeFormat           string    // 时间戳格式
    CallerEnabled        bool      // 包含调用者信息
    CallerSkipFrameCount int       // 调用者跳过帧数
    ServiceName          string    // 服务名称字段
    ServiceVersion       string    // 版本字段
}
```

### 中间件配置

```go
type MiddlewareConfig struct {
    Logger                *Logger       // 日志器实例
    SkipPaths             []string      // 跳过日志记录的路径
    SkipFunc              func(*http.Request) bool // 自定义跳过函数
    LogLevel              Level         // 2xx 响应的日志级别
    WarnLevel             Level         // 4xx 响应的日志级别
    ErrorLevel            Level         // 5xx 响应的日志级别
    IncludeRequestID     bool          // 生成/传播请求 ID
    RequestIDHeader      string        // 请求 ID 的头名称
    IncludeLatency       bool          // 记录请求持续时间
    IncludeHeaders       bool          // 记录请求头
    SensitiveHeaders     []string      // 需要脱敏的头
    IncludeQuery         bool          // 记录查询参数
    SensitiveQueryParams []string      // 需脱敏的 query 键（nil=不脱敏；空切片=使用默认列表）
    IncludeBody          bool          // 记录请求体（仅 Fiber 支持 body；慎用）
    MaxBodySize          int           // 记录的最大请求体大小
    TrustedProxies       []string      // 代理 IP/CIDR，用于从 X-Forwarded-For 解析客户端 IP
}
```

**敏感数据：** 默认会记录 query；URL 中常含 token、密码等。可通过 `SensitiveQueryParams`（默认会脱敏 password、token、code、secret、api_key 等）在日志中脱敏；设为 `nil` 可关闭 query 脱敏。`IncludeBody` 默认关闭，开启可能记录凭证，仅建议在非敏感路径使用或先脱敏再记录。

## 测试

```bash
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 许可证

Apache License 2.0
