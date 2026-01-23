## WIP

We are currently working on embedding a Node.js runtime environment into the app and have made progress with the initial coding. This is a simple Node.js project, and the build artifacts of this project can be utilized within CatVodApp.

Due to the differences across platforms, there are certain functionalities within the Node.js runtime that not available, including but not limited to 
 - `wasm`
 - `jit` on macos & ios



Dev `npm run dev`

Build `npm run build`

### Docker（开发模式：直接用当前目录代码）

在 `CatPawOpen/` 目录下：

- 构建并启动：`docker compose up -d --build`

说明：

- 容器会把当前目录挂载到 `/app`，等价于直接跑本地代码（适合开发调试自定义脚本）。
- 端口：`3006`（compose 默认映射 `3006:3006`）。
- 数据库文件：`db.json`（位于项目根目录）。若本地不存在，容器首次启动会自动创建空的 `db.json`。
- 依赖：`node_modules` 使用独立 volume，并在启动时从镜像内置依赖自动填充，避免容器启动时反复安装依赖。
- 改了依赖（`package*.json`）后需要重新构建：`docker compose up -d --build`；如依赖异常可执行 `docker compose down -v` 重新生成 `node_modules` volume。

### Custom Source 站点（custom_source）

- 将自定义站点脚本放到：`CatPawOpen/custom_spider/`
- 支持递归子目录与多种扩展名：`.js` / `.mjs` / `.cjs`
- 可选：为任意脚本添加同名清单来控制加载方式：`<script>.manifest.json`（例如 `foo.js.manifest.json`）
  - `{"enabled": false}`：禁用该脚本
  - `{"format": "vm"}`（默认）：VM 沙盒方式加载（兼容各类打包脚本）
  - `{"format": "esm"}`：按原生 ESM `import()` 加载（适合你后续新增的“非打包”脚本）
  - `{"format": "cjs"}`：按 CommonJS `require()` 加载
- 启动时会加载该目录下所有 `.js`（忽略 `_` 开头文件）
- 查看加载状态：`/custom_source`

### Go Proxy（可选）

用于浏览器侧把部分网盘播放地址注册到独立的 Go 流式透传服务（降低 Node 侧并发/CPU 压力）。

- Go 服务目录：`/root/TV_Server/go_proxy`（对外反代域名可单独配置）
- GoProxy 设置：由 `TV_Server` 管理后台保存（`goproxy_enabled / goproxy_servers` 等），并由前端在播放时决定是否使用

播放流程（重要）：
- 客户端请求 `CatPawOpen` 获取播放地址（以及 `header` 等必要参数）
- 客户端请求 `GoProxy` 注册 `{url, headers}`（`POST /register`）
- 客户端使用 `GoProxy` 返回的 token 地址播放（`GET /<token>`）

说明：
- `CatPawOpen` 不会与 `GoProxy` 通信；是否使用 `GoProxy` 由 `TV_Server` 前端决定。
- `CatPawOpen` 的“直链模式”会影响播放地址：开启后尽量返回直链；关闭后会返回 `CatPawOpen` 内置 proxy 地址。
- Quark 的 `download_url` 仍由 `CatPawOpen` 解析后返回给客户端；解析过程可能会等待一段时间（最长约 60 秒）。

## Nginx反代配置

`
add_header Access-Control-Allow-Origin $http_origin always;
add_header Access-Control-Allow-Credentials true always;
add_header Access-Control-Allow-Methods "GET,POST,PUT,DELETE,OPTIONS" always;
add_header Access-Control-Allow-Headers "Content-Type,X-TV-User,Authorization,Range,If-Range" always;
add_header Access-Control-Expose-Headers "Accept-Ranges,Content-Range,Content-Length" always;
`
