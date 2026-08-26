# Security Portal

**Security Portal** là nền tảng quét bảo mật website tự động cho đội ngũ kỹ thuật và kỹ sư bảo mật. Hệ thống phân tích rủi ro theo baseline OWASP, tạo **Technical Report** với findings, bằng chứng (evidence) và khuyến nghị khắc phục.

> Tài liệu này là hướng dẫn sử dụng tổng thể (cài đặt, cấu hình, vận hành, API). Hướng dẫn ngắn gọn trong app nằm ở `docs/GIOI_THIEU.md` (menu **Chức năng → Giới thiệu**).

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Kiến trúc](#2-kiến-trúc)
3. [Cấu trúc thư mục](#3-cấu-trúc-thư-mục)
4. [Yêu cầu](#4-yêu-cầu)
5. [Cài đặt & chạy](#5-cài-đặt--chạy)
6. [Cấu hình](#6-cấu-hình)
7. [Cài scanner tools (tuỳ chọn)](#7-cài-scanner-tools-tuỳ-chọn)
8. [Hướng dẫn sử dụng](#8-hướng-dẫn-sử-dụng)
9. [Tham chiếu API](#9-tham-chiếu-api)
10. [Bảo mật & quyền riêng tư](#10-bảo-mật--quyền-riêng-tư)
11. [Vận hành & giám sát](#11-vận-hành--giám-sát)
12. [Scripts kiểm thử API (PowerShell)](#12-scripts-kiểm-thử-api-powershell)
13. [Hạn chế & lộ trình](#13-hạn-chế--lộ-trình)

---

## 1. Tổng quan

Security Portal quét một website mục tiêu và trả về báo cáo bảo mật. Các nhóm khả năng chính:

| Nhóm | Khả năng |
|---|---|
| **Baseline HTTP** | Reachability, HTTPS/TLS, Security Headers, Server Fingerprint, Cookie Security, CORS, Information Disclosure |
| **Authenticated Scan** | Đăng nhập (Form / HTTP Basic / GraphQL) rồi quét khu vực sau login |
| **Source-assisted** | Shallow clone Git, trích route/API từ source (ASP.NET, Next.js, OpenAPI, Express, GraphQL) |
| **Mạng** | Port Scan (Naabu), DNS Security (dnsx), WAF Detection (wafw00f) |
| **Khám phá** | Directory Discovery (Feroxbuster/FFUF), Sensitive File Scan, Technology Detection, Screenshot (Gowitness) |
| **Lỗ hổng** | Vulnerability Scan (Nuclei) |

**Nguyên tắc hoạt động của tools:**

- Check **Built-in** (HTTP probe, header analyzer, cookie inspector, …) **luôn chạy** trong API.
- Tool ngoài (Naabu, Nuclei, Feroxbuster, FFUF, dnsx, wafw00f, Gowitness, …) được gọi khi **đã chọn trong cấu hình** **và** binary có trên `PATH` / `SCANNER_TOOLS_PATH` của host/API container.
- Nếu binary **thiếu** → hệ thống **fallback** về probe tích hợp hoặc sinh finding placeholder (mức Info) để báo cáo vẫn hoàn chỉnh.

Giao diện hỗ trợ **tiếng Việt / tiếng Anh** (chuyển ngôn ngữ tức thì ở góc header).

---

## 2. Kiến trúc

```
Frontend (SPA tĩnh)
   │  HTTP (qua Nginx reverse proxy)
   ▼
SecurityPortal.API (.NET 10, ASP.NET Core)
   │
   ├── WebsiteScanProcessor (HostedService / poller)
   │        ├── Built-in HTTP probes
   │        ├── Authenticated login (Form/Basic/GraphQL)
   │        ├── SourceRouteInventoryAnalyzer (LibGit2Sharp)
   │        └── ExternalToolRunner (Naabu/Nuclei/Ferox/FFUF/…)
   │
   ├── PostgreSQL 16   → website_scans (config/findings JSON)
   ├── MinIO           → artifact routes.json (source scan)
   ├── Redis 7         → cache / health
   ├── RabbitMQ 3.13   → message bus (workers/scheduler)
   └── Workers / Scheduler / Orchestrator (skeleton)
```

| Thành phần | Vai trò | Trạng thái |
|---|---|---|
| `SecurityPortal.API` | Xử lý scan website, auth login, source inventory, báo cáo | ✅ Hoạt động |
| `SecurityPortal.Scheduler` | Lịch quét định kỳ | Skeleton |
| `SecurityPortal.Orchestrator` | Điều phối pipeline | Skeleton |
| `SecurityPortal.Notification` | Gửi thông báo (SMTP/OpenAI) | Skeleton |
| `SecurityPortal.ReportEngine` | Xuất báo cáo | Skeleton |
| `SecurityPortal.Worker.*` | Discovery / Fingerprint / Network / Screenshot / SSL / Web | Skeleton |
| PostgreSQL | Lưu `website_scans`, config & findings JSON | ✅ |
| MinIO | Lưu artifact `routes.json` | ✅ |
| Redis / RabbitMQ | Cache / message bus | ✅ (health) |
| Nginx | Phục vụ frontend + reverse proxy API + rate limit | ✅ |

> **Lưu ý:** Toàn bộ luồng scan website hiện chạy trong **API** (poller `WebsiteScanProcessor`). Các Worker/Orchestrator/Scheduler là khung (skeleton) cho lộ trình phân tán sau này.

---

## 3. Cấu trúc thư mục

```
SecurityPortal/
├── SecurityPortal.sln
├── Directory.Build.props / Directory.Packages.props   # Central Package Management
├── global.json                                          # Pin .NET SDK
├── docker-compose.yml / docker-compose.override.yml
├── .env / .env.example
├── full_scan_workflow.ps1                               # Luồng test end-to-end (register -> create scan -> monitor)
├── test_public_scan.ps1                                 # Test nhanh scan website public
├── advanced_authenticated_scan.ps1                      # Test scan có đăng nhập form + output chi tiết
├── API_TESTING_GUIDE.md                                 # API guide thực thi scan bằng PowerShell
├── TESTING_README.md                                    # Hướng dẫn tích hợp/testing đầy đủ
├── SCRIPT_INDEX.md                                      # Mục lục scripts và cách dùng nhanh
├── SESSION_COMPLETION_SUMMARY.md                        # Tổng hợp kết quả test gần nhất
├── docs/
│   └── GIOI_THIEU.md                                    # Hướng dẫn trong app
├── frontend/                                            # SPA tĩnh (vanilla JS)
│   ├── index.html / home.js                             # Trang chủ + form scan
│   ├── configure.html / configure.js                    # Cấu hình checks/tools
│   ├── history.html / history.js                        # Lịch sử scan
│   ├── report.html                                      # Xem/xuất báo cáo
│   ├── api-client.js / config-store.js / i18n.js
│   └── styles.css
├── infrastructure/
│   ├── docker/nginx/nginx.conf                          # Reverse proxy + rate limit
│   ├── docker/scanners/{Dockerfile,entrypoint.sh}       # Image chứa scanner CLIs
│   ├── postgres/init.sql
│   ├── prometheus/prometheus.yml
│   └── grafana/provisioning/
├── scripts/
│   ├── install-scanners.sh / install-scanners.cmd       # Build & extract scanner binaries
├── src/
│   ├── services/
│   │   ├── SecurityPortal.API/                          # Web API + scan processor
│   │   │   ├── Controllers/v1/{Auth,Scans}Controller.cs
│   │   │   ├── Services/{WebsiteScanProcessor,ExternalToolRunner,
│   │   │   │              SourceRouteInventoryAnalyzer,ScanHttpClientFactory,…}.cs
│   │   │   ├── Hubs/ScanProgressHub.cs                  # SignalR (skeleton)
│   │   │   └── Middleware/GlobalExceptionMiddleware.cs
│   │   ├── SecurityPortal.Scheduler/
│   │   ├── SecurityPortal.Orchestrator/
│   │   ├── SecurityPortal.Notification/
│   │   └── SecurityPortal.ReportEngine/
│   ├── shared/
│   │   ├── SecurityPortal.Domain/                       # Entities, ScanCatalog, Scanning, Security
│   │   ├── SecurityPortal.Application/                  # CQRS (MediatR) Features/{Auth,Scans}
│   │   ├── SecurityPortal.Contracts/
│   │   └── SecurityPortal.Infrastructure/               # Persistence, MinIO, JWT, …
│   └── workers/
│       └── SecurityPortal.Worker.{Discovery,Fingerprint,Network,Screenshot,SSL,Web}/
├── tests/
│   ├── unit/{SecurityPortal.Application.Tests,SecurityPortal.Domain.Tests}
│   └── integration/SecurityPortal.API.Tests
└── tools/scanners/                                      # Output của install-scanners (binaries)
```

**Stack chính:** .NET 10 · ASP.NET Core · MediatR (CQRS) · EF Core (Npgsql) · Serilog · JWT · SignalR · MinIO · Prometheus · Nginx · Docker Compose.

---

## 4. Yêu cầu

| Hạng mục | Yêu cầu |
|---|---|
| **Docker + Docker Compose** | Bắt buộc để chạy full stack |
| **.NET SDK 10** | Chỉ cần khi chạy API local (`dotnet run`) |
| **Scanner CLIs** | Tuỳ chọn — Naabu, Nuclei, Feroxbuster, FFUF, dnsx, wafw00f, Gowitness, WhatWeb |
| **RAM/Đĩa** | Khuyến nghị ≥ 4 GB RAM, ≥ 10 GB đĩa (nuclei-templates + binaries) |

> Không bắt buộc cài `git` trong container — source clone dùng **LibGit2Sharp** (native).

---

## 5. Cài đặt & chạy

### 5.1. Chạy full stack (Docker Compose) — khuyến nghị

```bash
# 1) Chuẩn bị biến môi trường
cp .env.example .env
#    Sửa JWT_SECRET_KEY, các password DB/Redis/MinIO/RabbitMQ trước khi deploy

# 2) Build & khởi động toàn bộ stack
docker compose up -d --build

# 3) Theo dõi log
docker compose logs -f api
```

**Cổng mặc định (host):**

| Dịch vụ | Cổng |
|---|---|
| Nginx (frontend + proxy) | `80` |
| API (dev override) | `5000` |
| PostgreSQL | `5432` |
| Redis | `6380` |
| RabbitMQ (mgmt) | `5672` / `15672` |
| MinIO (API / Console) | `9002` / `9003` |

**Kiểm tra nhanh:**

```bash
curl http://localhost/health/live          # liveness
curl http://localhost/health/ready         # readiness (postgres + redis)
curl http://localhost/api/v1/scans/build-info
curl http://localhost/api/v1/scans/tools-status   # tools nào có sẵn trên host
```

Trình duyệt: `http://localhost/` (frontend) · Swagger: `http://localhost/swagger/` (chỉ khi `ASPNETCORE_ENVIRONMENT=Development`).

### 5.2. Chạy API local (dev)

```bash
# 1) Chạy hạ tầng (postgres/redis/rabbitmq/minio)
docker compose up -d postgres redis rabbitmq minio

# 2) (Tuỳ chọn) Cài scanner binaries cho local
./scripts/install-scanners.sh
source tools/scanners/env.sh

# 3) Chạy API
cd src/services/SecurityPortal.API
dotnet run
```

`docker-compose.override.yml` đặt `ASPNETCORE_ENVIRONMENT=Development` và map API ra cổng `5000`.

### 5.3. Build lại sau khi đổi code API

```bash
docker compose build api
docker compose up -d api
```

> Frontend là file tĩnh — sửa xong chỉ cần reload trình duyệt (Nginx đã đặt `no-cache` cho shell HTML).

---

## 6. Cấu hình

### 6.1. Biến môi trường (`.env`)

| Biến | Mặc định | Mô tả |
|---|---|---|
| `DD_DATABASE_NAME/USER/PASSWORD` | `defectmanagement` / `postgres` / `aiassistant` | PostgreSQL |
| `REDIS_PASSWORD` | `redis` | Redis (bắt buộc password) |
| `RABBITMQ_USER/PASSWORD` | `guest` / `guest` | RabbitMQ |
| `MINIO_ACCESS_KEY/SECRET_KEY` | `minioadmin` | MinIO |
| `JWT_SECRET_KEY` | — | **Bắt buộc** ngoài Development. Sinh: `openssl rand -base64 64` |
| `SMTP_HOST/PORT/USERNAME/PASSWORD` | — | Notification (skeleton) |
| `OPENAI_API_KEY/MODEL` | — | Notification (skeleton) |
| `GRAFANA_USER/PASSWORD` | `admin` | Grafana |
| `ASPNETCORE_ENVIRONMENT` | `Production` | `Development` để bật Swagger |
| `REDIS_HOST_PORT` | `6380` | Cổng Redis trên host |
| `MINIO_API_PORT` / `MINIO_CONSOLE_PORT` | `9002` / `9003` | Cổng MinIO trên host |

### 6.2. Cấu hình scan (trong trình duyệt)

Cấu hình **checks / tools / report type** được lưu trong `localStorage` trình duyệt (không phải server). Mở **Chức năng → Cấu hình** để:

1. Tích chọn **Security Checks** (nhóm basic / owasp / recon / network / vuln).
2. Tích chọn **Tools** (built-in luôn bật; external bật khi binary có sẵn).
3. Chọn loại **Báo cáo**: `technical` (mặc định) · `executive` · `owasp-summary`.

### 6.3. Tool options (tuỳ chọn nâng cao)

Gửi kèm request Start (xem [API](#9-tham-chiếu-api)):

| Tool | Tham số | Mặc định |
|---|---|---|
| **Nuclei** | `Profile`, `Severity`, `Tags`, `ExposureTags`, `Concurrency`, `RateLimit`, `TimeoutSeconds`, `Retries`, `MaxDurationSeconds` | `balanced` / `medium,high,critical` / `exposure,config,backup,token,key,file` / 25 / 150 / 8 / 1 / 120 |
| **Naabu** | `Ports`, `Rate` | phổ biến / 200 |
| **Feroxbuster** | `Depth`, `Threads`, `TimeoutSeconds`, `MaxDurationSeconds` | 1 / 20 / 5 / 90 |
| **FFUF** | `Threads`, `TimeoutSeconds`, `MaxDurationSeconds`, `MatchCodes` | — / — / — / — |

---

## 7. Cài scanner tools (tuỳ chọn)

Scanner CLIs **không bắt buộc** — thiếu binary sẽ fallback về probe tích hợp. Để bật detection đầy đủ:

**Cách A — Docker (khuyến nghị):**

```bash
docker compose up -d --build scanners
docker compose up -d --force-recreate api
```

Image `securityportal-scanners` build các binary vào volume `scanners_data`, API mount read-only tại `/opt/scanners`.

**Cách B — Local (host):**

```bash
./scripts/install-scanners.sh          # Linux/macOS/Git Bash
# hoặc
scripts\install-scanners.cmd           # Windows

source tools/scanners/env.sh           # export SCANNER_TOOLS_PATH, PATH, PYTHONPATH, NUCLEI_TEMPLATES_PATH
cd src/services/SecurityPortal.API && dotnet run
```

**Kiểm tra tools có sẵn:**

```bash
curl http://localhost/api/v1/scans/tools-status
```

> `ExternalToolRunner` tìm binary theo thứ tự: `SCANNER_TOOLS_PATH` → `./scanners/bin` → `./tools/scanners/bin` → `/opt/scanners/bin` → `/shared/bin` → `PATH`.

---

## 8. Hướng dẫn sử dụng

### Bước 1 — Mở trang chủ

Truy cập `http://localhost/` (qua Nginx). Bố cục 2 cột:

| Cột trái | Cột phải |
|---|---|
| Nhập URL, đăng nhập scan, phân tích source | Technical Report, Cấu hình, Lịch sử hoặc Hướng dẫn |

### Bước 2 — Cấu hình scan (tuỳ chọn)

**Chức năng → Cấu hình** → tích checks/tools → chọn loại báo cáo.

### Bước 3 — Nhập mục tiêu

1. **Website URL** — ví dụ `https://example.com`.
   > ⚠️ Host private / loopback / link-local / IMDS bị **chặn** (chống SSRF).
2. (Tuỳ chọn) **Scan với đăng nhập** — chọn loại auth + credential.
3. (Tuỳ chọn) **Phân tích source code (Git)** — repo URL + PAT nếu private.

### Bước 4 — Bắt đầu scan

Nhấn **Bắt đầu scan**. Response trả `accessToken` **một lần** — trình duyệt lưu để xem lại / dừng / xóa. Báo cáo hiển thị ở cột phải khi hoàn tất.

### Bước 5 — Đọc findings

- Findings `auth.*` — khi bật đăng nhập (cookie session, API base sau login, so sánh path ẩn danh vs đã đăng nhập, probe GraphQL).
- Findings `source.*` — khi bật phân tích source.
- `source.authz.candidate` = nghi ngờ route có `:id` thiếu guard org/clinic — **cần xác minh thêm** bằng test runtime (dual-account).

### Bước 6 — Lịch sử & xuất báo cáo

- **Chức năng → Lịch sử** — mở lại scan cũ (chỉ hiện scan mà trình duyệt còn giữ access token).
- **Export Report** — tải báo cáo (PDF/HTML) từ báo cáo hiện tại.

### Bước 7 — Hướng dẫn trong app

**Chức năng → Giới thiệu** — bản hướng dẫn tóm tắt (cùng nội dung panel phải).

### Theo dõi tiến trình & dừng scan

- UI **poll** `GET /api/v1/scans/{id}` (header `X-Scan-Token`) mỗi vài giây; dùng `AbortController` để tránh chồng request.
- Nút **Dừng scan** gọi `POST /api/v1/scans/{id}/cancel`.

---

## 9. Tham chiếu API

Base path: `/api/v1` · Phiên bản: `v1` · Auth: JWT (Bearer) cho nhóm Auth; Scan API dùng **owner access token** (`X-Scan-Token`).

### Auth

| Method | Đường dẫn | Mô tả | Auth |
|---|---|---|---|
| `POST` | `/auth/login` | Đăng nhập email/password | Anonymous |
| `POST` | `/auth/register` | Đăng ký tài khoản + tổ chức | Anonymous |
| `POST` | `/auth/refresh` | Làm mới access token | Anonymous |
| `POST` | `/auth/revoke` | Thu hồi refresh token (logout) | Anonymous |
| `POST` | `/auth/change-password` | Đổi mật khẩu | JWT |
| `PUT` | `/auth/profile` | Cập nhật hồ sơ | JWT |

### Scans

| Method | Đường dẫn | Mô tả | Auth |
|---|---|---|---|
| `GET` | `/scans/build-info` | Build stamp + cấu hình runtime | Anonymous |
| `GET` | `/scans/tools-status` | Tools nào có sẵn trên host | Anonymous |
| `GET` | `/scans/catalog` | Danh mục checks/tools/reports | Anonymous |
| `POST` | `/scans` | **Bắt đầu scan** (trả `accessToken` 1 lần) | Anonymous |
| `GET` | `/scans/{id}` | Trạng thái + báo cáo | `X-Scan-Token` |
| `POST` | `/scans/history` | Liệt kê scan **mà caller sở hữu** (gửi `tokens`) | Anonymous |
| `GET` | `/scans` | **Deprecated** — trả rỗng (chống IDOR) | Anonymous |
| `DELETE` | `/scans` | Xóa scan (cần `accessTokens` khớp) | Anonymous |
| `POST` | `/scans/{id}/cancel` | Dừng scan | `X-Scan-Token` |

### Ví dụ: bắt đầu scan

```bash
curl -X POST http://localhost/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "https://example.com",
    "reportType": "technical",
    "checks": ["reachability","https-tls","security-headers","server-fingerprint","cookie-security","cors-policy","information-disclosure","port-scan","directory-discovery","sensitive-file-scan","vulnerability-scan","technology-detection","dns-security","waf-detection"],
    "auth": {
      "type": "form",
      "loginUrl": "https://example.com/login",
      "username": "user",
      "password": "pass",
      "successUrlContains": "/dashboard"
    },
    "source": {
      "repositoryUrl": "https://github.com/org/app.git",
      "branch": "main",
      "token": "ghp_xxx"
    }
  }'
```

Response `201` trả `WebsiteScanDto` chứa `id` và **`accessToken`** (chỉ xuất hiện 1 lần).

### Ví dụ: xem kết quả

```bash
curl http://localhost/api/v1/scans/{id} -H "X-Scan-Token: <accessToken>"
```

### Ví dụ: lịch sử (chống IDOR)

```bash
curl -X POST http://localhost/api/v1/scans/history \
  -H "Content-Type: application/json" \
  -d '{ "tokens": { "<scan-guid>": "<accessToken>" } }'
```

> `tokens` rỗng → trả danh sách rỗng (không liệt kê toàn bộ).

### Health

| Đường dẫn | Mô tả |
|---|---|
| `GET /health/live` | Liveness |
| `GET /health/ready` | Readiness (PostgreSQL + Redis) |

---

## 10. Bảo mật & quyền riêng tư

| Nội dung | Cách xử lý |
|---|---|
| **Password scan** | AES-GCM mã hóa trước khi lưu DB; API chỉ trả `UsernameMasked` |
| **PAT / Git token** | Mã hóa tương tự password; không xuất hiện trong findings (đã sanitize) |
| **Access token scan** | Hash SHA-256 lưu DB; plaintext chỉ trả **một lần** lúc Start |
| **Mục tiêu HTTP** | Chặn private/loopback/link-local/IMDS (SSRF) |
| **Log request** | `LoggingBehavior` redact field password/token |
| **Nginx** | Rate limit `20r/s` (burst 40) cho `/api/`; security headers + CSP |
| **`JWT_SECRET_KEY`** | Bắt buộc ngoài Development |

**Quy tắc vận hành:**

- ❌ **Không** dán PAT vào ô Repository URL.
- ❌ **Không** commit token vào Git.
- ⚠️ Nếu PAT lộ → **revoke ngay** trên Git forge và tạo token mới.

---

## 11. Vận hành & giám sát

| Công cụ | Địa chỉ |
|---|---|
| **Prometheus** | metrics qua `app.UseMetricServer()` / `UseHttpMetrics()` |
| **Grafana** | dashboards provisioned tại `infrastructure/grafana/provisioning/` |
| **RabbitMQ mgmt** | `http://localhost:15672` |
| **MinIO console** | `http://localhost:9003` |
| **Swagger** | `http://localhost/swagger/` (Development) |

**Logs:** Serilog → console + file `logs/log-.txt` (rolling theo ngày).

**Khởi động lại sau đổi code:**

```bash
docker compose build api && docker compose up -d api
```

---

## 12. Scripts kiểm thử API (PowerShell)

Repo hiện có bộ script PowerShell để chạy smoke test và test workflow scan tự động.

| Script | Mục đích | Ghi chú |
|---|---|---|
| `test_public_scan.ps1` | Test nhanh scan website public | Chạy nhanh, phù hợp kiểm tra health API scan |
| `full_scan_workflow.ps1` | Workflow đầy đủ: register user, tạo scan, monitor trạng thái, đọc kết quả | Script khuyến nghị để verify end-to-end |
| `advanced_authenticated_scan.ps1` | Scan có cấu hình đăng nhập form, output findings chi tiết hơn | Đã tương thích Windows PowerShell 5.1 |

Ví dụ chạy nhanh trên Windows:

```powershell
cd "d:\Security Portal"
powershell -File .\test_public_scan.ps1
powershell -File .\full_scan_workflow.ps1
```

Tài liệu chi tiết:

- `API_TESTING_GUIDE.md`
- `TESTING_README.md`
- `SCRIPT_INDEX.md`

---

## 13. Hạn chế & lộ trình

| Tính năng | Trạng thái |
|---|---|
| HTTP baseline + auth surface | ✅ Hoạt động |
| Source route inventory (LibGit2Sharp) | ✅ Hoạt động |
| External tools (Naabu/Nuclei/Ferox/…) | ✅ Gọi nếu có trên PATH; không thì fallback |
| Scan access token (chống IDOR) | ✅ Start trả token; Get/Cancel/History/Delete yêu cầu |
| SSRF host safety | ✅ Chặn private/loopback/IMDS |
| Cross-org BOLA runtime (2 account) | 🔜 Chưa có |
| SignalR progress realtime | 🔜 UI dùng HTTP poll |
| Đăng ký / JWT đầy đủ | 🔜 Scan API vẫn AllowAnonymous + owner token |

---

*Tài liệu cập nhật theo phiên bản hiện tại của Security Portal (build stamp `2026-08-07.8`).*
