# index-of-scanner
基于协程并发的Web敏感文件扫描器，精准探测备份文件、配置泄露及版本控制目录暴露风险，为渗透测试与安全防护提供专业级资产测绘方案。
![Python版本](https://img.shields.io/badge/Python-3.8%2B-blue)
![授权协议](https://img.shields.io/badge/License-MIT-green)
![版本](https://img.shields.io/badge/Release-v2.1.0-orange)

专业级Web敏感文件扫描工具，为渗透测试工程师量身定制的资产测绘解决方案

## 🚀 核心功能

- **智能敏感文件探测**  
  精准识别`备份文件`、`版本控制`、`密钥证书`等12类敏感资产
- **三重检测引擎**  
  `扩展名匹配` + `路径正则` + `复合压缩检测`三维验证机制
- **高效并发扫描**  
  动态协程控制（30-200并发），平均扫描速度达1500 URL/分钟
- **智能去重机制**  
  基于可扩展布隆过滤器，内存占用<2MB/万级URL
- **专业报告输出**  
  自动生成Excel兼容的CSV报告（UTF-8-SIG编码）

## 🛠️ 使用指南

### 基础扫描
```bash
# 命令行模式
python scanner.py targets.txt

# 交互模式
python scanner.py
> 请输入目标文件路径: targets.txt
```

### 目标文件格式
`targets.txt`示例：
```text
http://example.com
admin.example.com/api/
192.168.1.100:8080
```

### 实时输出预览
![image](https://github.com/user-attachments/assets/e20de44f-ea8e-40a7-b355-0b99cc858cac)


## 📊 报告样本

`安全扫描报告_20240520_1432.csv`示例：

| 风险等级 | URL地址                  | 检测依据            |
|----------|--------------------------|---------------------|
| 高危     | http://example.com/.git/ | 路径匹配: \.(git|svn)/ |
| 高危     | http://example.com/db.sql | 敏感扩展名: sql     |

## ⚙️ 配置定制

修改`CONFIG`字典调整扫描策略：
```python
CONFIG = {
    "max_depth": 3,          # 爬取深度
    "concurrency_range": (30, 200),  # 动态并发区间
    "sensitive_ext": {       # 扩展名黑名单
        'sql', 'bak', 'pem', ...  
    },
    "sensitive_paths": [     # 路径正则规则
        re.compile(r'/(backup|archive)/', re.I),
        ...
    ]
}
```

## ⚠️ 注意事项

1. 遵循授权测试原则，禁止非法扫描
2. 建议在隔离环境测试后再用于生产
3. 可通过调整`concurrency_range`优化资源占用
4. 扫描日志详见同目录`scan.log`

## 📜 许可协议

本项目基于 [MIT License](LICENSE) 开放使用，禁止用于非法用途

```

---

**版本更新**  
`v2.1.0` 新增功能：
- 智能交互式启动模式
- 动态进度监控系统
- CSV报告中文编码优化
- 高危端口自动阻断机制

