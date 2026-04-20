# GraRasp

GraRasp 是一个轻量级 Java RASP（Runtime Application Self-Protection，运行时应用自保护）项目，基于 `Java Agent + Javassist` 在运行时对目标类进行插桩，用于检测并阻断高风险行为，例如命令执行、JNDI 注入、SpEL 注入、恶意脚本执行以及内存马注册。

## 功能特性

- 运行时拦截以下高风险入口：
  - `Runtime.exec`
  - `ProcessBuilder.start`
  - `InitialContext.lookup`
  - `ScriptEngine.eval`
  - Spring SpEL 表达式解析
- 检测以下类型的内存马组件：
  - Filter
  - Servlet
  - Listener
  - Valve
  - WebSocket Endpoint
- 支持周期性容器扫描与风险评分
- 支持阻断模式，通过抛出 `SecurityException` 终止高风险行为
- 支持通过 Webhook 发送告警
- 基于 `ServiceLoader` 的插件化中间件适配

## 支持范围

| 能力 | Tomcat | WebLogic | Spring Boot |
|------|--------|----------|-------------|
| Filter 检测 | 是 | 是 | 是 |
| Servlet 检测 | 是 | 是 | 是 |
| Listener 检测 | 是 | 是 | 是 |
| Valve 检测 | 是 | 否 | 是 |
| WebSocket 检测 | 是 | 否 | 是 |
| SpEL 检测 | 否 | 否 | 是 |

## 项目结构

```text
GraRasp/
+-- Grasp-agent/        # Java Agent 入口与字节码转换器
+-- Grasp-core/         # 核心检测逻辑、扫描器、配置、工具类
+-- Grasp-spy/          # 插桩代码与核心逻辑之间的桥接层
`-- Grasp-plugins/      # 中间件适配插件
    +-- plugin-tomcat/
    +-- plugin-weblogic/
    `-- plugin-springboot/
```

## 工作原理

1. JVM 通过 `-javaagent` 加载 `Grasp-agent`
2. `Grasp-agent` 注册 `ClassFileTransformer`
3. 在类加载阶段对核心 JDK 类和中间件类进行插桩
4. 注入后的字节码通过 `Spy.check(...)` 上报运行时事件
5. `Grasp-core` 负责执行检测、阻断、告警与后台扫描

## 构建

### 环境要求

- JDK 8 及以上
- Maven 3.6 及以上

### 编译打包

```bash
mvn clean package -DskipTests
```

主要产物：

```text
Grasp-agent/target/Grasp-agent.jar
```

### 运行测试

```bash
mvn test
```

## 使用方式

### 直接附加到 Java 应用

```bash
java -javaagent:/path/to/Grasp-agent.jar -jar app.jar
```

### 指定配置文件

```bash
java -javaagent:/path/to/Grasp-agent.jar -Dgrarasp.config=/path/to/grarasp.yml -jar app.jar
```

### Tomcat 场景

可通过 `JAVA_OPTS` 注入 agent：

```bash
export JAVA_OPTS="$JAVA_OPTS -javaagent:/path/to/Grasp-agent.jar"
```

## 配置说明

GraRasp 会按以下顺序查找配置文件，并使用第一个存在的文件：

1. `-Dgrarasp.config=/path/to/grarasp.yml`
2. `./grarasp.yml`
3. `./conf/grarasp.yml`
4. `./config/grarasp.yml`
5. `~/.grarasp/grarasp.yml`

配置示例：

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

### 关键配置项

- `block_mode`
  - `true`：阻断可疑行为，并在高风险场景下尝试自动清理组件
  - `false`：仅监控和记录，不阻断
- `scan.enabled`
  - 是否开启后台周期性扫描
- `scan.interval`
  - 扫描间隔，单位为毫秒
- `rules.*`
  - 控制各类检测规则是否启用
- `alert.webhook`
  - 用于接收告警的 HTTP 地址
- `whitelist.components`
  - 扫描时忽略的组件名称
- `whitelist.classes`
  - 扫描时忽略的类名前缀

## 检测能力

### 命令执行

检测以下类型的可疑进程创建行为：

- 反弹 Shell 特征
- 危险命令与命令链
- 命令替换与管道执行
- 可疑调用来源

### JNDI 注入

检测以下类型的 JNDI lookup：

- `ldap://`
- `ldaps://`
- `rmi://`
- `dns://`
- 常见 DNSLog / 回连域名
- 编码或混淆后的 lookup 名称

### SpEL 注入

检测以下类型的危险表达式：

- 危险的 `T(...)` 类型引用
- 使用 `new` 创建危险对象
- 反射调用链
- 字符串拼接绕过
- Unicode、八进制、HTML 实体等混淆方式

### 内存马检测

可检测运行时注册或已存在的以下组件：

- Filter
- Servlet
- Listener
- Valve
- WebSocket Endpoint

扫描器会结合以下因素计算风险分值：

- 类名模式
- 已知工具特征
- 类加载器特征
- 反射与进程执行痕迹
- `CodeSource` 与继承关系

## 日志示例

启动日志：

```text
[GraRasp] Core initialized v1.5.0. Protection Online.
[GraRasp] Block mode: true
[GraRasp] Enhanced Memory Shell Scanner started (interval: 30000ms)
[GraRasp] Hooked java.lang.ClassLoader successfully!
[GraRasp] Hooked java.lang.Runtime.exec() successfully!
[GraRasp] Hooked javax.naming.InitialContext.lookup() successfully!
```

检测日志：

```text
========================================
[GraRasp] HIGH RISK Memory Shell Detected!
Type:      Filter
Name:      evilFilter
Class:     com.evil.Shell$$Lambda
Risk:      85/100
========================================
```

阻断日志：

```text
========================================
[GraRasp Security Alert] WebSocket MemShell Injection Detected! path=/ws-rce, class=class Test$1
Type:    WebSocket MemShell
Action:  Blocked
========================================
```

## 开发说明

### 模块职责

- `Grasp-agent`
  - `premain` 入口
  - 注册 Transformer
  - 对已加载核心类执行重转换
- `Grasp-core`
  - 检测器
  - 扫描引擎
  - 配置加载
  - 反射与辅助工具
- `Grasp-spy`
  - 提供插桩代码与核心逻辑之间的事件桥接
- `Grasp-plugins`
  - 提供中间件特定的 Hook 与适配逻辑

### 测试命令

运行核心模块测试：

```bash
mvn -pl Grasp-core test
```

运行全量测试：

```bash
mvn test
```

## 已知限制

- 当前检测逻辑以启发式规则为主，仍可能存在误报或漏报
- 不同中间件版本的内部实现差异可能影响兼容性
- 某些 Hook 的生效依赖类加载时机与 JVM 能力
- 当前自动化测试主要覆盖核心行为，完整集成场景仍需进一步扩展

## License

MIT
