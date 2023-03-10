# 项目介绍

工作需要对大量IP进行漏洞扫描，使用 Nessus 手动上传文件很繁琐。利用 `Nessus Api` 来自动化完成任务

# 功能

1. 批量创建扫描任务
2. 自动化运行所有任务
3. 统一导出报告

# 使用说明

1. 生成 API Keys

登录 Nessus 生成 API Keys

`Settings` -> `My Account` -> `API Keys`

2. 运行前先修改配置文件 `config.ini` 

```
[settings]
host = https://127.0.0.1:8834
ak = 3b...8
sk = 36...6
create_task = zh_sec_q1

```

`host` 为 Nessus 地址，`create_task` 为扫描任务名

3. 批量上传扫描的文件放在 `file` 文件夹内
4. 运行 `Nessus_auto_task.py`

# 后期

1. 整理扫描结果，只输出特点漏洞
2. 中文翻译