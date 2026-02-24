# GraRasp v1.5.0

轻量级 Java RASP (Runtime Application Self-Protection) 防御框架，基于 Java Agent 技术实现运行时安全防护。

## 核心能力

### 内存马防护
| 类型 | Tomcat | WebLogic | Spring Boot |
|------|--------|----------|-------------|
| Filter | ✅ | ✅ | ✅ |
| Servlet | ✅ | ✅ | ✅ |
| Listener | ✅ | ✅ | ✅ |
| Valve | ✅ | - | ✅ |
| WebSocket | ✅ | - | ✅ |

### 漏洞防护
- **命令执行**: Runtime.exec / ProcessBuilder 检测，反弹 Shell 识别
- **JNDI 注入**: Log4j2 漏洞防护，恶意协议拦截 (ldap/rmi/dns)
- **SpEL 注入**: 表达式注入检测，支持 Unicode/编码绕过识别
- **反序列化**: ClassLoader 底层 Hook，TemplatesImpl 攻击拦截

### 巡检机制
- 风险评分 (0-100)，分级告警
- 高风险组件自动清除 (≥80分)
- 增量扫描，性能优化
- Webhook 告警推送

## 项目结构

```
GraRasp/
├── Grasp-agent/          # Agent 入口，类加载隔离
├── Grasp-core/           # 核心检测逻辑
│   ├── config/           # 配置管理 (RaspConfig)
│   ├── detector/         # 检测器 (Command/Jndi/SpEL)
│   └── util/             # 工具类 (ReflectionCache)
├── Grasp-spy/            # 探针桥接层
└── Grasp-plugins/        # 中间件插件
    ├── plugin-tomcat/    # Tomcat 支持
    ├── plugin-weblogic/  # WebLogic 支持
    └── plugin-springboot/# Spring Boot 支持
```

## 快速开始

### 1. 编译

```bash
mvn clean package -DskipTests
```

产物: `Grasp-agent/target/Grasp-agent.jar`

### 2. 部署

```bash
# Tomcat
java -javaagent:/path/to/Grasp-agent.jar -jar app.jar

# 或修改 catalina.sh
export JAVA_OPTS="$JAVA_OPTS -javaagent:/path/to/Grasp-agent.jar"

# 指定配置文件
java -javaagent:/path/to/Grasp-agent.jar -Dgrarasp.config=/path/to/grarasp.yml -jar app.jar
```

### 3. 配置

创建 `grarasp.yml`:

```yaml
# 阻断模式: true=拦截+清除, false=仅监控
block_mode: true

# 巡检配置
scan:
  enabled: true
  interval: 30000  # 毫秒

# 检测规则
rules:
  spel: true
  classloader: true
  runtime_exec: true
  jndi: true

# 告警 Webhook
alert:
  webhook: http://your-server/alert

# 白名单
whitelist:
  components:
    - myCustomFilter
  classes:
    - com.mycompany.
```

配置文件查找顺序:
1. `-Dgrarasp.config=/path/to/grarasp.yml`
2. `./grarasp.yml`
3. `./conf/grarasp.yml`
4. `~/.grarasp/grarasp.yml`

## 运行效果

### 启动日志

```
[GraRasp] Core initialized v1.5.0. Protection Online.
[GraRasp] Block mode: true
[GraRasp] Enhanced Memory Shell Scanner started (interval: 30000ms)
[GraRasp] ✅ Hooked java.lang.ClassLoader successfully!
[GraRasp] ✅ Hooked java.lang.Runtime.exec() successfully!
[GraRasp] ✅ Hooked javax.naming.InitialContext.lookup() successfully!
```

### 拦截日志

```
========================================
[GraRasp] HIGH RISK Memory Shell Detected!
Type:      Filter
Name:      evilFilter
Class:     com.evil.Shell$$Lambda
Risk:      85/100
========================================
[GraRasp] CLEANED Filter: evilFilter
```

### WebSocket 内存马拦截

```
========================================
[GraRasp Security Alert] 🚨 WebSocket MemShell Injection Detected! path=/ws-rce, class=class Test$1
Type:    WebSocket MemShell
Action:  Blocked
========================================
```

## 风险评分规则

| 特征 | 分值 |
|------|------|
| 动态代理类 ($$/$Proxy) | +20 |
| CGLIB/Enhancer | +15 |
| 恶意标识 (shell/exploit/payload) | +40 |
| 已知工具 (behinder/godzilla) | +50 |
| 匿名类 ($数字) | +10 |
| 无包名类 | +15 |
| 非标准 ClassLoader | +15 |
| TransletClassLoader | +30 |
| 无 CodeSource | +15 |
| 继承 AbstractTranslet | +40 |

阈值:
- **30分**: 低风险告警
- **60分**: 中高风险告警
- **80分**: 自动清除 (需 block_mode=true)

## Webhook 告警格式

```json
{
  "level": "HIGH RISK",
  "type": "Filter",
  "name": "evilFilter",
  "class": "com.evil.Shell$$Lambda",
  "risk": 85,
  "timestamp": 1708765432000
}
```

## License

MIT
