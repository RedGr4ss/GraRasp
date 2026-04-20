# GraRasp v1.5.0

GraRasp 是一个面向 Java Web 场景的轻量级 RASP（Runtime Application Self-Protection）项目，基于 `Java Agent + Javassist` 在运行时完成类插桩、危险行为检测、内存马扫描与阻断。

## 核心能力

### 1. 漏洞利用检测

- 命令执行检测：拦截 `Runtime.exec` 和 `ProcessBuilder.start`
- JNDI 注入检测：识别 `ldap://`、`rmi://`、`dns://` 等危险 lookup
- SpEL 注入检测：支持 Unicode、拼接绕过、反射链等模式识别
- ScriptEngine 执行检测：识别脚本中的危险 Java 调用
- 类加载检测：在 `ClassLoader#defineClass` 阶段分析可疑字节码来源

### 2. 内存马扫描与清理

当前支持以下组件的运行时发现与风险分析：

| 类型 | Tomcat | WebLogic | Spring Boot |
|------|--------|----------|-------------|
| Filter | Yes | Yes | Yes |
| Servlet | Yes | Yes | Yes |
| Listener | Yes | Yes | Yes |
| Valve | Yes | No | Yes |
| WebSocket | Yes | No | Yes |

扫描阶段会结合类名、类加载器、反射痕迹、已知工具特征等因素计算风险分值。高风险对象在 `block_mode=true` 时会尝试自动清理。

### 3. 可扩展插件机制

GraRasp 通过 `ServiceLoader` 发现插件，不同中间件的 Hook 逻辑解耦在独立模块中：

- `plugin-tomcat`
- `plugin-weblogic`
- `plugin-springboot`

## 项目结构

```text
GraRasp/
├── Grasp-agent/        # Agent 入口与字节码转换器
├── Grasp-core/         # 核心检测、扫描、配置、工具类
├── Grasp-spy/          # 业务类与核心逻辑之间的桥接层
└── Grasp-plugins/      # 中间件适配插件
    ├── plugin-tomcat/
    ├── plugin-weblogic/
    └── plugin-springboot/
```

## 构建

```bash
mvn clean package -DskipTests
```

主要产物：

```text
Grasp-agent/target/Grasp-agent.jar
```

## 使用方式

### 1. 直接附加到 Java 应用

```bash
java -javaagent:/path/to/Grasp-agent.jar -jar app.jar
```

### 2. 指定配置文件

```bash
java -javaagent:/path/to/Grasp-agent.jar -Dgrarasp.config=/path/to/grarasp.yml -jar app.jar
```

### 3. Tomcat 场景

可在 `catalina.sh` 或启动参数中加入：

```bash
export JAVA_OPTS="$JAVA_OPTS -javaagent:/path/to/Grasp-agent.jar"
```

## 配置示例

创建 `grarasp.yml`：

```yaml
block_mode: true

scan:
  enabled: true
  interval: 30000

rules:
  spel: true
  classloader: true
  runtime_exec: true
  jndi: true

alert:
  webhook: http://your-server/alert

whitelist:
  components:
    - myCustomFilter
  classes:
    - com.mycompany.
```

配置文件查找顺序：

1. `-Dgrarasp.config=/path/to/grarasp.yml`
2. `./grarasp.yml`
3. `./conf/grarasp.yml`
4. `./config/grarasp.yml`
5. `~/.grarasp/grarasp.yml`

## 运行示例

### 启动日志

```text
[GraRasp] Core initialized v1.5.0. Protection Online.
[GraRasp] Block mode: true
[GraRasp] Enhanced Memory Shell Scanner started (interval: 30000ms)
[GraRasp] Hooked java.lang.ClassLoader successfully!
[GraRasp] Hooked java.lang.Runtime.exec() successfully!
[GraRasp] Hooked javax.naming.InitialContext.lookup() successfully!
```

### 检测日志

```text
========================================
[GraRasp] HIGH RISK Memory Shell Detected!
Type:      Filter
Name:      evilFilter
Class:     com.evil.Shell$$Lambda
Risk:      85/100
========================================
[GraRasp] CLEANED Filter: evilFilter
```

### 阻断日志

```text
========================================
[GraRasp Security Alert] WebSocket MemShell Injection Detected! path=/ws-rce, class=class Test$1
Type:    WebSocket MemShell
Action:  Blocked
========================================
```

## 风险评分示例

| 特征 | 分值 |
|------|------|
| 动态代理类 `$$` / `$Proxy` | +20 |
| CGLIB / Enhancer | +15 |
| 恶意关键词 `shell` / `payload` / `exploit` | +40 |
| 已知工具特征 `behinder` / `godzilla` | +50 |
| 匿名内部类 | +10 |
| 无包名类 | +15 |
| 非标准类加载器 | +15 |
| `TransletClassLoader` | +30 |
| `CodeSource` 缺失 | +15 |
| 继承 `AbstractTranslet` | +40 |

默认处理阈值：

- `>= 30`：低风险告警
- `>= 60`：中高风险告警
- `>= 80`：自动清理（需要 `block_mode=true`）

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

## 当前局限

- 规则主要基于启发式检测，仍可能存在误报和漏报
- 不同中间件版本的内部实现差异较大，兼容性仍需更多实测
- 当前测试覆盖仍偏基础，更适合原型验证而非直接生产落地

## License

MIT
