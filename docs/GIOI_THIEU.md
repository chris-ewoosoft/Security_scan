# Security Portal — Hướng dẫn sử dụng

## 1. Tổng quan

**Security Portal** là nền tảng quét bảo mật website tự động cho đội ngũ kỹ thuật và kỹ sư bảo mật. Hệ thống phân tích rủi ro theo baseline OWASP, tạo **Technical Report** với findings, bằng chứng và khuyến nghị khắc phục.

Giao diện hỗ trợ **tiếng Việt / tiếng Anh** (chuyển ngôn ngữ tức thì ở góc header).

**Bố cục trang chủ**

| Cột trái | Cột phải |
|---|---|
| Nhập URL, đăng nhập scan, phân tích source | Technical Report, Cấu hình, Lịch sử hoặc Hướng dẫn |

**Menu header:** `Trang chủ` · `Chức năng ▾` (Cấu hình · Lịch sử · Giới thiệu)

---

## 2. Tính năng chính

### 2.1 Quét bảo mật website (HTTP)

| Nhóm | Check | Mô tả |
|---|---|---|
| **Cơ bản** | Khả năng truy cập | HTTP status, thời gian phản hồi |
| | HTTPS / TLS | Xác minh HTTPS và tín hiệu TLS |
| | Security Headers | CSP, HSTS, X-Frame-Options, … |
| | Server Fingerprint | `Server` / `X-Powered-By` |
| | Cookie Security | `Secure`, `HttpOnly`, `SameSite` |
| | CORS Policy | `Access-Control-Allow-Origin` |
| | Information Disclosure | Header nhạy cảm |
| | **Authenticated Scan** | Đăng nhập rồi quét khu vực sau login |
| **Source-assisted** | **Source Route Inventory** | Shallow clone Git, trích route/API từ source, gợi ý thiếu tenant guard |
| **Mạng** | Port Scan | TCP probe; chạy **Naabu** nếu binary có trên PATH |
| | DNS Security | Resolve DNS; dùng **dnsx** nếu có |
| | WAF Detection | Fingerprint header; dùng **wafw00f** nếu có |
| **Khám phá** | Directory Discovery | Wordlist tích hợp; **Feroxbuster** / **FFUF** nếu có trên PATH |
| | Sensitive File Scan | `.env`, `.git`, backup, … |
| | Technology Detection | Suy luận stack từ header |
| | Screenshot | **Gowitness** nếu có; không thì Info placeholder |
| **Lỗ hổng** | Vulnerability Scan | **Nuclei** nếu có; không thì Info placeholder |

> Check **Built-in** luôn chạy trong API. Tool ngoài (Naabu, Nuclei, Ferox, …) được gọi khi **đã chọn trong cấu hình** và binary có trên `PATH` của host/API container; nếu thiếu thì fallback probe tích hợp hoặc finding placeholder.

### 2.2 Scan có đăng nhập (Authenticated Scan)

Bật **Scan với đăng nhập** trên form trang chủ:

| Loại | Khi nào dùng |
|---|---|
| **Form login** | Website có form username/password |
| **HTTP Basic** | Trang/API bảo vệ Basic Auth |
| **GraphQL API** | SPA/backend GraphQL — dán endpoint `/graphql`, không phải trang `/login` |

**Trường bổ sung**

- **Clinic / Hospital ID** — multi-tenant (ví dụ hệ thống y tế Clever)
- **Login URL** — tuỳ chọn; bắt buộc với GraphQL
- **URL sau đăng nhập chứa** — marker xác nhận login thành công

**Sau khi login thành công**, portal bổ sung findings:

- Cookie session (`Secure` / `HttpOnly`)
- API/GraphQL base phát hiện sau login
- So sánh path **ẩn danh vs đã đăng nhập** (`auth.surface.authz_diff`)
- Probe GraphQL anonymous vs authenticated

### 2.3 Phân tích source code (Source Route Inventory)

Bật **Phân tích source code (Git)** trên form trang chủ:

| Ô | Mô tả |
|---|---|
| **Git repository URL** | URL `https://` tới repo (không dùng `git@` SSH) |
| **Branch** | Tuỳ chọn, mặc định branch mặc định của repo |
| **Token / PAT** | Tuỳ chọn cho repo private — quyền **read** repository |

**Quy trình**

1. Shallow clone qua **LibGit2Sharp** (không cần cài `git` trong container)
2. Quét file source: ASP.NET, Next.js, OpenAPI, Express, GraphQL schema
3. Sinh findings: `source.routes.found`, `source.authz.candidate`, …
4. Bổ sung path từ source vào probe authenticated (ví dụ `/event`, `/event/export`)
5. (Tuỳ chọn) Lưu `routes.json` lên MinIO

**Lấy PAT (GitHub)**

1. GitHub → Settings → Developer settings → Personal access tokens
2. Tạo token **read-only** (`Contents: Read` hoặc fine-grained tương đương)
3. Dán vào ô **Token / PAT** — **không** dán token vào ô Repository URL
4. Repo public có thể bỏ trống token

**Giới hạn:** worktree phân tích tối đa ~512 MB (không tính `.git`, `node_modules`, `bin/obj`). Clone timeout ~90 giây.

### 2.4 Báo cáo bảo mật

| Thành phần | Mô tả |
|---|---|
| **Risk Score** | 0–100 (điểm giảm dần theo số finding cùng severity; có High → tối thiểu 55) |
| **Risk Level** | Low &lt; 40 · Medium 40–69 · High ≥ 70 |
| **Findings** | Mức độ, tiêu đề, chi tiết, evidence, khuyến nghị, bước tái hiện |
| **Executive Summary** | Tóm tắt rủi ro |

| Loại báo cáo | Đối tượng |
|---|---|
| Technical Report | Kỹ sư bảo mật |
| Executive Summary | Quản lý |
| OWASP-oriented Summary | Nhóm theo baseline OWASP |

Nút **Export Report** xuất PDF/HTML từ báo cáo hiện tại.

### 2.5 Theo dõi tiến trình

Giao diện **poll** `GET /api/v1/scans/{id}` (header `X-Scan-Token`) mỗi vài giây. Có thể **Dừng scan** khi đang chạy. Poll dùng `AbortController` để tránh chồng request.

### 2.6 Lịch sử quét

**Chức năng → Lịch sử:** chỉ hiện scan mà trình duyệt còn giữ access token (`localStorage`). API `GET /scans` mở không còn liệt kê toàn bộ (chống IDOR). Xóa cần gửi `accessTokens` khớp.

---

## 3. Hướng dẫn từng bước

### Bước 1 — Mở trang chủ

Truy cập Security Portal qua trình duyệt (thường qua Nginx reverse proxy).

### Bước 2 — Cấu hình scan (tuỳ chọn)

1. **Chức năng → Cấu hình**
2. Tích **Security Checks** và **Tools**
3. Chọn loại **Báo cáo**
4. Cấu hình lưu trong `localStorage` trình duyệt

### Bước 3 — Nhập mục tiêu

1. **Website URL** — ví dụ `https://example.com` (host private/loopback/IMDS bị chặn chống SSRF)
2. (Tuỳ chọn) **Scan với đăng nhập** — điền credential và loại auth
3. (Tuỳ chọn) **Phân tích source code** — repo Git + PAT nếu private

### Bước 4 — Bắt đầu scan

Nhấn **Bắt đầu scan**. Response trả `accessToken` một lần — trình duyệt lưu để xem lại / dừng / xóa. Báo cáo hiển thị ở cột phải khi hoàn tất.

### Bước 5 — Đọc findings

- Chú ý findings **auth.*** khi bật đăng nhập
- Chú ý findings **source.*** khi bật phân tích source
- Finding `source.authz.candidate` = nghi ngờ route có `:id` thiếu guard org/clinic — cần xác minh thêm bằng test runtime (dual-account)

### Bước 6 — Lịch sử & xuất báo cáo

- **Chức năng → Lịch sử** — mở lại scan cũ
- **Export Report** — tải báo cáo

### Bước 7 — Hướng dẫn trong app

**Chức năng → Giới thiệu** — bản hướng dẫn tóm tắt (cùng nội dung panel phải).

---

## 4. Bảo mật và quyền riêng tư

| Nội dung | Cách xử lý |
|---|---|
| Password scan | AES-GCM mã hóa trước khi lưu DB; API chỉ trả `UsernameMasked` |
| PAT / Git token | Mã hóa tương tự password; không xuất hiện trong findings (đã sanitize) |
| Access token scan | Hash SHA-256 lưu DB; plaintext chỉ trả một lần lúc Start |
| Mục tiêu HTTP | Chặn private/loopback/link-local/IMDS (SSRF) |
| Log request | `LoggingBehavior` redact field password/token |
| PAT lộ | Revoke ngay trên Git forge và tạo token mới |
| `ScanSecrets:Key` | Bắt buộc ngoài Development |

**Không** dán PAT vào ô Repository URL. **Không** commit token vào Git.

---

## 5. Kiến trúc (tóm tắt)

```
Frontend (SPA) ──HTTP──▶ SecurityPortal.API (.NET 10)
                              │
                    WebsiteScanProcessor (poller)
                              │
                    PostgreSQL (scans, findings JSON)
                    MinIO (route inventory artifacts)
                    Redis · RabbitMQ · Workers (skeleton)
```

| Thành phần | Ghi chú |
|---|---|
| API | Xử lý scan website, auth login, source inventory |
| Workers | Docker services có sẵn; chưa wire đầy đủ cho WebsiteScan |
| PostgreSQL | `website_scans`, config/findings JSON |
| MinIO | Artifact `routes.json` khi source scan thành công |
| Nginx | Phục vụ frontend + reverse proxy API |

---

## 6. Triển khai

```bash
docker compose up -d
docker compose build api    # sau khi đổi code API
docker compose up -d api
```

Swagger: `http://localhost:<port>/swagger`

---

## 7. Hạn chế hiện tại & lộ trình

| Tính năng | Trạng thái |
|---|---|
| HTTP baseline + auth surface | ✅ Hoạt động |
| Source route inventory | ✅ Hoạt động (LibGit2Sharp) |
| External tools (Naabu/Nuclei/Ferox/…) | ✅ Gọi nếu có trên PATH; không thì fallback |
| Scan access token (chống IDOR) | ✅ Start trả token; Get/Cancel/History/Delete yêu cầu |
| SSRF host safety | ✅ Chặn private/loopback/IMDS |
| Cross-org BOLA runtime (2 account) | 🔜 Chưa có |
| SignalR progress realtime | 🔜 UI dùng HTTP poll |
| Đăng ký / JWT đầy đủ | 🔜 Scan API vẫn AllowAnonymous + owner token |

---

*Tài liệu cập nhật theo phiên bản hiện tại của Security Portal (authenticated scan, source inventory, menu Chức năng).*
