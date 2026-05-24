# 基于 gmssl 的国密加密解密应用

这个作业程序使用 Python `gmssl` 库实现了 `SM2`、`SM3`、`SM4` 的常见实验功能：

- 固定密钥与随机密钥生成
- 字符串加密/解密与正确性验证
- 文件分块加密/解密
- 加密解密时间统计
- CPU 与内存占用监控
- 不同数据量下的吞吐量计算
- 图像文件头保留参数

## 运行环境

请使用你已经创建好的 `crypto_exper` 虚拟环境：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py self-test
```

## 功能说明

### 1. 密钥生成

随机生成 SM2 密钥对：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py generate-key --algorithm sm2
```

使用固定 SM2 私钥并自动推导公钥：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py generate-key --algorithm sm2 --private-key-hex 0000000000000000000000000000000000000000000000000000000000000001
```

随机生成 SM4 密钥与 IV：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py generate-key --algorithm sm4 --mode cbc
```

### 2. 字符串加密解密

SM2 字符串加密：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py encrypt-text --algorithm sm2 --text "hello gmssl" --public-key-hex <SM2公钥>
```

SM4 字符串加密：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py encrypt-text --algorithm sm4 --text "hello gmssl" --key-hex 0123456789abcdeffedcba9876543210 --mode cbc --iv-hex 000102030405060708090a0b0c0d0e0f
```

SM4 字符串解密：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py decrypt-text --algorithm sm4 --ciphertext <密文> --key-hex 0123456789abcdeffedcba9876543210 --mode cbc --iv-hex 000102030405060708090a0b0c0d0e0f
```

### 3. SM3 摘要

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py hash-text --text "integrity check"
```

说明：`SM3` 是单向摘要算法，不支持解密。

### 4. 文件分块加密解密

普通文件使用自描述 `bundle` 格式：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py encrypt-file --algorithm sm4 --input .\sample.bin --layout bundle --mode cbc --chunk-size 1MB
```

解密：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py decrypt-file --input .\sample.bin.gms --key-hex <SM4密钥>
```

使用 `SM2 + SM4` 混合方式加密大文件：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py encrypt-file --algorithm sm2-sm4 --input .\sample.bin --public-key-hex <SM2公钥>
```

对应解密：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py decrypt-file --input .\sample.bin.gms --private-key-hex <SM2私钥>
```

### 5. 图像文件头处理

如果希望加密后仍尽量保留图像格式头，可以使用：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py encrypt-file --algorithm sm4 --input .\image.bmp --layout raw --keep-header-bytes 54 --key-hex 0123456789abcdeffedcba9876543210 --mode cbc --iv-hex 000102030405060708090a0b0c0d0e0f
```

也可以启用自动头长度预设：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py encrypt-file --algorithm sm4 --input .\image.png --layout raw --auto-image-header --key-hex 0123456789abcdeffedcba9876543210 --mode cbc --iv-hex 000102030405060708090a0b0c0d0e0f
```

注意：

- `raw` 模式不会写入容器元数据，解密时必须再次提供相同参数。
- 对 `JPG/PNG` 这类压缩图像，仅保留文件头不一定能保证加密文件完全可视化，但解密后可以恢复原文件。

### 6. 性能测试

测试不同数据量的加密解密时间、CPU、内存和吞吐量：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py benchmark --algorithm sm4 --sizes 64KB,1MB,5MB --chunk-size 1MB --metrics-out .\benchmark.json
```

程序会输出 JSON 结果，其中包含：

- `seconds`
- `cpu_avg_percent`
- `cpu_peak_percent`
- `memory_avg_mb`
- `memory_peak_mb`
- `throughput_mb_s`

## 自测

运行内置冒烟测试：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_app.py self-test
```

运行单元测试：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" -m unittest -v
```

## 本地网页端

当前推荐的交互方式是本地网页端。相比桌面 GUI，它更适合展示中文界面、实验说明、性能图表和多区域结果面板。

启动方式：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" web_app.py
```

启动后，在浏览器访问：

```text
http://127.0.0.1:5000
```

网页端包含：

- 主页面：文本实验区、文件与图片实验区、性能测试区
- 帮助页面：实验流程、图片头处理说明、常见错误说明
- 中文界面：更适合课程实验演示
- 图表输出：生成加密时间对比图和吞吐量对比图

## 桌面 GUI

如果还想使用旧的桌面界面，也可以启动：

```powershell
& "C:\Users\29969\.conda\envs\crypto_exper\python.exe" crypto_gui.py
```

但从实际体验看，课程实验更建议使用网页端。
