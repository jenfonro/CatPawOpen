## CatPawOpen（TV_Server Node 服务）

Dev：`npm run dev`

Build：`npm run build`

说明：不同平台的 Node runtime 可能会缺少部分能力（例如 `wasm`、macOS/iOS 的 `jit` 等）。

### Docker（开发模式：直接用当前目录代码）

在 `CatPawOpen/` 目录下：

- 构建并启动：`docker compose up -d --build`

说明：

- 容器会把当前目录挂载到 `/app`，等价于直接跑本地代码（适合开发调试自定义脚本）。
- 端口：`3006`（compose 默认映射 `3006:3006`）。
- 数据文件：`db.json`、`config.json`（位于 `CatPawOpen/` 根目录）。
- 依赖：`node_modules` 使用独立 volume，并在启动时从镜像内置依赖自动填充，避免容器启动时反复安装依赖。
- 改了依赖（`package*.json`）后需要重新构建：`docker compose up -d --build`；如依赖异常可执行 `docker compose down -v` 重新生成 `node_modules` volume。

### 配置（`config.json`）

- `proxy`: string，全局出站代理地址（为空表示不启用）。
- `panResolver`: boolean，是否启用“内置网盘解析”（拦截百度/夸克的 `play`）。

运行时也可通过接口读写：

- `GET /admin/settings`：读取（返回 `proxy` + `panBuiltinResolverEnabled`）
- `PUT /admin/settings`：写入（body：`{ proxy, panBuiltinResolverEnabled }`）

### Custom Source（自定义脚本）

- 将自定义站点脚本放到：`CatPawOpen/custom_spider/`
- 支持递归子目录与多种扩展名：`.js` / `.mjs` / `.cjs`
- 启动时会加载该目录下脚本（忽略 `_` 开头文件）
- 查看加载状态：`/custom_source`

支持两类脚本：

- **spider 脚本**：注册 `/spider/<key>/<type>/...`
- **api plugin 脚本**：导出 `apiPlugins = [{ prefix, plugin }]`，注册 `/api/...`（例如 `/api/baidu`、`/api/quark`）


### Debug 环境变量

- `CATPAW_DEBUG=1`：仅在自定义脚本加载失败时打印完整堆栈
- `NET_DEBUG=1`：输出自定义脚本的网络 trace（`[trace:<file>]`）
- `SPIDER_DEBUG=1`：仅输出“站点脚本”的出站请求（`[sites:<file>]`），并过滤掉夸克/百度/UC 等网盘域名
- `PAN_DEBUG=1`：输出内置网盘解析的 play 流程日志（`[pan] ...`）


### 播放流程（重要）：
- 客户端请求 `CatPawOpen` 获取播放地址（以及 `header` 等必要参数）
- 客户端请求 `GoProxy` 注册 `{url, headers}`（`POST /register`）
- 客户端使用 `GoProxy` 返回的 token 地址播放（`GET /<token>`）

说明：
- `CatPawOpen` 不会与 `GoProxy` 通信；是否使用 `GoProxy` 由 `TV_Server` 前端决定。

## Nginx反代配置

需要确保把外部访问域名信息转发给 CatPawOpen（用于播放地址改写）：

- `proxy_set_header Host $http_host;`
- `proxy_set_header X-Forwarded-Proto $scheme;`
- `proxy_set_header X-Forwarded-Host $host;`
- `proxy_set_header X-Forwarded-Port $server_port;`

（如需 CORS，可按你的 TV_Server 前端场景配置 `Access-Control-Allow-*`。）
