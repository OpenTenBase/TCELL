## 简介

TCELL是由北京工业大学可信计算北京市重点实验室与腾讯TDSQL团队联合科研打造的，基于可信计算的轻量级开源动态度量模块，旨在为数据库与云原生关键组件提供运行时完整性度量，通过持续监测、收集与验证，让关键软件在运行过程中“可度量、可审计”，保障数据库环境安全可信。该项目于2026年正式捐赠给开放原子基金会OpenTenBase社区进行孵化。

该系统旨在通过Linux内核模块技术和国密SM3算法，构建针对数据库关键组件的内存防篡改统一框架。通过框架提供的周期性内存区域扫描与动态基准比对机制，便于使用者在不中断业务运行的情况下，实时监测并发现代码注入、内存篡改等高级威胁。针对数据库系统面临的运行时无文件攻击难题，提供了内核级的可信安全保障，解决了传统静态文件完整性校验无法覆盖运行时内存状态的问题，能够有效提升数据库在复杂环境下的内生安全能力。
## 目录结构

*   **`dynamic_baselib/`**: 核心基准库模块。
    *   维护一个基于红黑树的内存数据库，存储进程 PID 和对应的进程代码段与动态链接库的哈希基准。
    *   导出内核符号（API）供度量模块调用（注册、校验、删除）。
    *   使用 `kprobe` 挂载 `do_exit`，在进程退出时自动清理对应的基准数据。
    *   提供 `debugfs` 接口用于调试。
*   **`dynamic_measure/`**: 度量扫描模块。
    *   启动一个内核线程 (`kmeasure_scanner`)。
    *   **初始扫描**: 遍历系统数据库相关进程，建立初始基准。
    *   **周期扫描**: 按照设定间隔（默认 30s）轮询进程，计算其代码段与链接库的SM3度量值。
    *   **处置逻辑**: 如果度量值与基准不一致，视为完整性受损。
*   **`encryption/`**: 加密算法库。
    *   包含国密 SM3 哈希算法的内核态实现。
*   **`include/`**: 公共头文件。
    *   定义数据结构、宏和跨模块 API 接口。

## 功能特性

*   **运行时动态度量**: 不依赖磁盘文件校验，直接读取内存页（Page）计算哈希，可检测无文件攻击（Fileless Attack）或内存修改。
*   **国密 SM3 算法**: 采用自主可控的 SM3 摘要算法确保数据唯一性。
*   **生命周期管理**: 自动监听进程创建（首次扫描注册）与退出（自动清理基准），无需人工干预。
*   **主动防御**: 检测到篡改时实时告警。
*   **调试接口**: 支持通过 `/sys/kernel/debug/baseline_db/` 查看当前基准库状态。

## 编译与运行

### 环境要求
*   Linux Kernel : 建议 5.4 及以上版本.
    *   5.4 (Ubuntu 18.04 LTS 等) 至 6.8 (Ubuntu 22.04 LTS 等)。
    *   代码包含针对 Kernel 5.8+ mmap_read_lock API 变更的兼容性处理。
    *   必须安装对应的内核头文件（linux-headers-$(uname -r)）。
* **GCC**: 建议 **7.5.0 及以上版本**
    * 注：编译内核模块所用的 GCC 版本应与编译当前运行内核时的 GCC 版本保持一致（可通过 `cat /proc/version` 查看）。
* **Make**: GNU Make 3.81 及以上。

### 编译
在项目根目录下（或分别进入子目录）执行：

```bash
# 编译 dynamic_baselib 与 dynamic_measure
make
```
编译成功后：

   dynamic_baselib/ 目录下将生成 dynamic_baselib.ko
   
   dynamic_measure/ 目录下将生成 measure.ko

### 加载模块
**注意**: 必须严格遵守加载顺序， `measure.ko` 依赖于 `dynamic_baselib.ko` 导出的符号。

1. **加载基准库模块**
   ```bash
   sudo insmod dynamic_baselib/dynamic_baselib.ko
   ```
   *加载成功后，会在 `/sys/kernel/debug/baseline_db/` 创建调试接口。*

2. **加载度量模块**
   ```bash
   # 默认扫描间隔 30 秒
   sudo insmod dynamic_measure/measure.ko
   
   # 或者指定扫描间隔 (例如 10 秒)
   sudo insmod dynamic_measure/measure.ko scan_interval_sec=10
   ```
   *加载后，内核日志 (`dmesg`) 将显示初始扫描进度。*

### 卸载模块
卸载顺序与加载顺序相反：

```bash
sudo rmmod measure
sudo rmmod dynamic_baselib
```

## 调试 (Debugging)

加载 `dynamic_baselib` 后，可以使用 debugfs 查看内部状态：

```bash
# 查看当前已注册的进程基准
sudo cat /sys/kernel/debug/baseline_db/dump
```

## 注意事项

1.  **强制终止风险**: 当前版本的 `dynamic_measure` 模块在检测到哈希不匹配时不会**直接发送 SIGKILL 信号终止进程**。在生产环境部署前，请务必评估业务影响，建议先在测试环境验证，后续可自行选择是否开启。
2.  **性能影响**: 频繁的全量内存哈希计算会消耗一定的 CPU 资源，建议根据实际负载调整 `scan_interval_sec` 参数。
