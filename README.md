# VulnGadget

`VulnGadget` 是一个基于 Java ASM 的静态分析工具，用于从 Jar 包中提取 Web 入口方法、构建方法调用链，并识别潜在漏洞调用路径。

当前项目主要面向 Java Web / Spring Boot 场景，能够从控制器入口出发，分析请求参数到危险方法之间的调用关系，并输出适合人工复核的结果文件。

## Features

- 扫描目录中的 Jar 包，支持递归解析嵌套 Jar
- 自动识别 Spring Boot 控制器及其请求路径
- 从入口方法构建调用链，并处理父类 / 接口实现带来的方法分派
- 内置多类危险 sink 规则，可识别潜在调用路径
- 支持通过 `source.yaml` 自定义非 Spring 场景的入口定义
- 输出多种分析结果，便于排查、归档和二次处理

## Supported Checks

项目当前内置以下漏洞类型检测规则：

- `RCE`
- `SSRF`
- `Deserialization`
- `XXE`
- `FileVuln`
- `Sql`

危险方法规则位于 [src/main/resources/methodInfo.yaml](/c:/Users/Administrator/Desktop/VulnGadget/src/main/resources/methodInfo.yaml)。

## How It Works

整体流程大致如下：

1. 扫描目标 Jar 及其嵌套 Jar 中的 `.class`
2. 使用 ASM 提取类信息、方法信息、调用关系和注解信息
3. 识别 Web 入口方法
4. 从入口方法向下构建调用路径
5. 将调用路径与 `methodInfo.yaml` 中的危险 sink 进行匹配
6. 输出可读文本和 JSON 结果

Spring Boot 模式入口类：

- [src/main/java/org/vulngedget/SpringbootMain.java](/c:/Users/Administrator/Desktop/VulnGadget/src/main/java/org/vulngedget/SpringbootMain.java)

自定义入口模式入口类：

- [src/main/java/org/vulngedget/CustomMain.java](/c:/Users/Administrator/Desktop/VulnGadget/src/main/java/org/vulngedget/CustomMain.java)

## Project Structure

```text
src/main/java/org/vulngedget
├─ SpringbootMain.java           Spring Boot 扫描入口
├─ CustomMain.java               自定义入口扫描入口
├─ visitor/                      ASM 访问器，负责采集类/方法/注解/调用关系
├─ cache/                        扫描期缓存与全局索引
├─ reference/                    方法、类、路径、调用细节等数据结构
├─ flows/                        调用流和污点相关分析代码
└─ util/                         输出、模板、注解、规则加载等工具类

src/main/resources
├─ methodInfo.yaml               危险 sink 规则
├─ source.yaml                   自定义 source / 注解入口配置
├─ templates/                    输出模板
└─ scanJar/                      示例扫描目录
```

## Requirements

- JDK 8+
- Maven 3.6+

## Build

```bash
mvn clean package -DskipTests
```

已验证当前项目可以正常完成 `mvn clean package -DskipTests` 构建。

## Usage

### 1. Spring Boot 模式

适用于通过 Spring MVC / Spring Boot 注解暴露 Web 接口的项目。

```bash
java -cp "target/classes;<dependency-classpath>" org.vulngedget.SpringbootMain "<package-prefix>" "<jar-directory>"
```

示例：

```bash
java -cp "target/classes;<dependency-classpath>" org.vulngedget.SpringbootMain "com/example" "D:\\scanJar"
```

参数说明：

- `package-prefix`：业务代码包前缀，使用 JVM 内部类名格式，例如 `com/example`
- `jar-directory`：待扫描 Jar 所在目录

默认参数：

- `package-prefix`: `nds/ehcache`
- `jar-directory`: `src/main/resources/scanJar/`

### 2. 自定义入口模式

适用于非 Spring Boot 框架，或者需要手工指定 source / 注解入口的场景。

```bash
java -cp "target/classes;<dependency-classpath>" org.vulngedget.CustomMain "<package-prefix>" "<jar-directory>"
```

在该模式下，入口规则由 [src/main/resources/source.yaml](/c:/Users/Administrator/Desktop/VulnGadget/src/main/resources/source.yaml) 控制。

## Dependency Classpath

命令行运行时需要包含 Maven 依赖。可以先生成依赖 classpath：

```bash
mvn --% -q dependency:build-classpath -Dmdep.outputFile=target\deps.cp
```

然后在 PowerShell 中运行：

```powershell
$deps = Get-Content target\deps.cp -Raw
java -cp "target\classes;$deps" org.vulngedget.SpringbootMain "com/example" "D:\scanJar"
```

如果你更习惯图形界面，直接在 IDEA 中运行 `SpringbootMain` 或 `CustomMain` 会更方便。

## Output Files

扫描完成后，项目根目录会生成以下文件：

- `result.txt`：按漏洞类型汇总的命中结果
- `webpath.txt`：识别到的 Web 路径映射
- `allFlow.txt`：所有入口调用链
- `completeFlow.txt`：更完整的漏洞调用细节文本输出
- `completeFlow.json`：结构化 JSON 输出，便于后续处理

其中 `completeFlow.json` 更适合：

- 二次开发
- 构建前端展示
- 与其他安全分析平台对接

## Configuration

### `methodInfo.yaml`

用于配置危险 sink。每类漏洞由 `className + methodName + desc` 组成。

你可以在这里扩展更多规则，例如：

- 增加新的反序列化入口
- 增加更多 SQL 执行 API
- 增加文件读写、模板执行、表达式执行等敏感方法

### `source.yaml`

用于自定义入口识别规则，支持两类方式：

- 通过注解识别入口类 / 入口方法
- 通过显式类名 + 方法签名指定 source 方法

适合扩展到：

- Solon
- 自研 MVC 框架
- 网关 / RPC / 消息消费入口

## Disclaimer

本项目仅用于授权测试、安全研究和代码审计学习，请勿用于任何未授权目标。
