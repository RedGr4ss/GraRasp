# GraRasp (Java Runtime Application Self-Protection)

GraRasp 是一个基于微内核架构的轻量级 Java RASP 防御框架。它通过 Java Agent 技术在运行时对关键类进行字节码插桩，能够实时检测并阻断 RCE、内存马等高危攻击。

## 🛡️ 核心功能

* **微内核架构**：采用 `Agent` + `SPI` + `Plugin` 设计，核心与插件分离，易于扩展。
* ** Tomcat 内存马防御**：
    * ✅ Servlet 内存马
    * ✅ Filter 内存马
    * ✅ Listener 内存马
    * ✅ Valve (Pipeline) 内存马
    * ✅ WebSocket 内存马


## 🏗️ 项目结构

* **Grasp-agent**: Java Agent 入口，负责类加载隔离与 SPI 插件分发。
* **Grasp-core**: 核心逻辑层，包含状态检测算法与安全策略（SpyHandler）。
* **Grasp-spy**: 极简的探针桥接层，负责将 Hook 点流量导入 Core。
* **Grasp-plugins**: 插件模块，包含针对 Tomcat、Undertow 等中间件的具体 Hook 实现。

## 🚀 快速开始

### 1. 编译构建
在项目根目录执行 Maven 构建命令：
```bash
mvn clean install
```
构建成功后，Agent 包位于：Grasp-agent/target/Grasp-agent.jar

## 2. 启动配置
在目标 Java 应用（如 Tomcat、SpringBoot）的启动参数中添加：

```Bash
-javaagent:/path/to/Grasp-agent.jar
```
## 3. 运行效果
启动应用时，控制台将输出 GraRasp Logo 及插件加载信息。当检测到攻击（如 WebSocket 内存马注入）时，将输出如下阻断日志：

```Plaintext
[GraRasp Security Alert] 🚨 Memory Shell Detected!
Type:    memshell_websocket
Context: org.apache.catalina.core.StandardContext
State:   STARTED (Suspicious: Runtime Modification)
[GraRasp Action] 🚫 Blocked by Security Policy!
```
