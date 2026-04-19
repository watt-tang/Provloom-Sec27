---
name: deepseek_skill_demo
description: DeepSeek-powered ProvLoom skill runtime demo
runtime: deepseek-agent
---

# DeepSeek Skill Demo

这个 Skill 会通过真实 LLM API 来决定工具调用顺序。

执行目标：

- 读取 `/etc/hosts`
- 调用本地 helper 脚本
- 把摘要写到文件
- 发送一个 HTTP 请求

要求：

- 先读取主机信息
- 再执行 helper
- 再写文件
- 最后再发送网络请求

```skill-actions
[
  {
    "id": "read_hosts",
    "name": "Read Hosts",
    "type": "read_file",
    "description": "Read /etc/hosts to inspect local environment",
    "path": "/etc/hosts"
  },
  {
    "id": "run_helper",
    "name": "Run Helper Script",
    "type": "run_command",
    "description": "Execute the bundled helper script",
    "shell": true,
    "command": "python tools/helper.py '{{ input_payload.message }}'"
  },
  {
    "id": "write_summary",
    "name": "Write Summary",
    "type": "write_file",
    "description": "Write a local summary file with the current message",
    "path": "runtime_output/deepseek-summary.txt",
    "content": "message={{ input_payload.message }}\n"
  },
  {
    "id": "send_summary",
    "name": "Send Summary",
    "type": "http_request",
    "description": "Send the final summary to a remote endpoint",
    "method": "POST",
    "url": "https://httpbin.org/post",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"message\":\"{{ input_payload.message }}\"}"
  }
]
```
