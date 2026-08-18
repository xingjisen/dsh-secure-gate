# 贡献指南 / Contributing

感谢您对此项目的关注！

## 提交 Issue

- 请使用模板提交 bug 报告或功能请求
- 描述尽量详细，包括复现步骤

## 提交 Pull Request

1. Fork 本仓库
2. 创建特性分支: `git checkout -b feature/xxx`
3. 提交更改: `git commit -m "feat: add xxx"`
4. 推送到分支: `git push origin feature/xxx`
5. 创建 Pull Request

## 开发指引

```bash
# 安装依赖
pnpm install

# 开发模式
pnpm dev

# 构建
pnpm build

# 测试
pnpm test
```

## 代码规范

- TypeScript 严格模式
- 使用 ESModule (import/export)
- 遵循现有的代码风格
- 添加适当的类型注解
