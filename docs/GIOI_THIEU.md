# Security Portal — Tài liệu giới thiệu phần mềm

## 1. Tổng quan

**Security Portal** là nền tảng quét bảo mật website tự động, được thiết kế cho các đội ngũ kỹ thuật và kỹ sư bảo mật. Hệ thống cho phép người dùng phân tích rủi ro bảo mật của một website (hoặc ứng dụng web) theo chuẩn OWASP và các tiêu chuẩn bảo mật thực tế, từ đó nhận báo cáo chi tiết về lỗ hổng, cấu hình sai và khuyến nghị khắc phục.

Phần mềm được xây dựng theo kiến trúc microservice, triển khai bằng Docker Compose, giao diện người dùng hoàn toàn bằng tiếng Việt và tiếng Anh (chuyển ngôn ngữ tức thì).

---

## 2. Tính năng chính

### 2.1 Quét bảo mật website

| Nhóm kiểm tra | Tên check | Mô tả |
|---|---|---|
| **Cơ bản (Built-in)** | Khả năng truy cập | HTTP response, thời gian phản hồi, mã trạng thái |
| | HTTPS / TLS | Xác minh site dùng HTTPS và cấu hình TLS cơ bản |
| | Security Headers | Phân tích CSP, HSTS, X-Frame-Options và các header bảo mật khác |
| | Server Fingerprint | Thu thập thông tin lộ qua `Server` / `X-Powered-By` |
| | Cookie Security | Kiểm tra cờ `Secure`, `HttpOnly`, `SameSite` |
| | CORS Policy | Đánh giá `Access-Control-Allow-Origin` và cấu hình CORS |
| | Information Disclosure | Phát hiện header nhạy cảm và dấu hiệu lộ thông tin |
| | Authenticated Scan | Quét khu vực sau đăng nhập (form/HTTP Basic/GraphQL) |
| **Mạng & Hạ tầng** | Port Scan | Quét cổng mở bằng Naabu |
| | DNS Security | Kiểm tra bản ghi DNS (A/AAAA/CNAME) bằng dnsx |
| | WAF Detection | Phát hiện Web Application Firewall bằng wafw00f |
| **Khám phá & Tình báo** | Directory Discovery | Tìm đường dẫn / thư mục ẩn (Feroxbuster, FFUF) |
| | Sensitive File Scan | Tìm file nhạy cảm (`.env`, backup, git, config) bằng Nuclei |
| | Technology Detection | Nhận diện CMS/framework/JS stack (WhatWeb, Wappalyzer) |
| | Screenshot | Chụp ảnh trang đích lưu chứng cứ (Gowitness + MinIO) |
| **Lỗ hổng** | Vulnerability Scan | Quét theo template CVE, misconfiguration bằng Nuclei |

### 2.2 Báo cáo bảo mật

Sau mỗi lượt quét, hệ thống tạo **Security Report** gồm:

- **Điểm rủi ro (Risk Score)**: 0–100, tính theo trọng số finding (High +25, Medium +12, Low +5, Info +0). Điểm 0 là an toàn nhất.
- **Risk Level**: `Low` (< 40) · `Medium` (40–69) · `High` (≥ 70)
- **Danh sách Findings**: mỗi finding gồm mức độ nghiêm trọng, tiêu đề, chi tiết kỹ thuật, bằng chứng, khuyến nghị và các bước tái hiện lỗi.
- **Executive Summary**: tóm tắt rủi ro tổng quan dành cho quản lý.

Ba loại báo cáo có thể chọn:

| Loại | Dành cho |
|---|---|
| **Technical Report** | Kỹ sư bảo mật — chi tiết kỹ thuật theo từng check và bằng chứng |
| **Executive Summary** | Quản lý — rủi ro tổng quan và khuyến nghị ưu tiên |
| **OWASP-oriented Summary** | Nhóm findings theo góc nhìn OWASP / baseline web |

### 2.3 Theo dõi tiến trình thời gian thực

Giao diện hiển thị trạng thái scan (`Queued → Running → Completed / Cancelled / Failed`) qua kết nối SignalR, không cần tải lại trang.

### 2.4 Lịch sử quét

Lưu lại toàn bộ lượt quét trước, cho phép xem lại báo cáo và xóa nhiều bản ghi cùng lúc.

### 2.5 Quản lý người dùng và tổ chức

- Hệ thống phân cấp: **Organization → User → Role → Permission**
- Ba vai trò mặc định: `Admin`, `SecurityEngineer`, `Viewer`
- Phân quyền chi tiết theo resource: `projects`, `assets`, `scans`, `findings`, `reports`, `users`, `audit`
- Xác thực JWT + Refresh Token; hỗ trợ đổi mật khẩu và cập nhật hồ sơ cá nhân

### 2.6 Kiểm toán (Audit Log)

Mọi thao tác quan trọng (tạo scan, thay đổi quyền, xóa dữ liệu) đều được ghi nhật ký đầy đủ: người dùng, hành động, địa chỉ IP, giá trị trước/sau thay đổi.

---

## 3. Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────┐
│                     Frontend (SPA)                  │
│   index.html · configure · history · report (JS)    │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP REST + SignalR
┌──────────────────────▼──────────────────────────────┐
│              SecurityPortal.API  (.NET 8)            │
│   Controllers v1 · SignalR Hub · JWT Auth · Swagger  │
└──────┬───────────────┬───────────────────────────────┘
       │               │ MassTransit / RabbitMQ
       │    ┌──────────▼──────────────────────────────┐
       │    │         Workers (microservices)          │
       │    │  Discovery · Fingerprint · Network       │
       │    │  Screenshot · SSL · Web                  │
       │    └──────────────────────────────────────────┘
       │
┌──────▼──────────────────────┐   ┌──────────────────┐
│   PostgreSQL (dữ liệu)      │   │   Redis (cache)  │
└─────────────────────────────┘   └──────────────────┘
┌─────────────────────────────┐   ┌──────────────────┐
│   Prometheus (metrics)      │──▶│  Grafana (charts)│
└─────────────────────────────┘   └──────────────────┘
┌─────────────────────────────┐
│   Loki + Serilog (logs)     │
└─────────────────────────────┘
```

**Công nghệ sử dụng:**

| Thành phần | Công nghệ |
|---|---|
| Backend API | .NET 8, Clean Architecture, CQRS, MediatR |
| Cơ sở dữ liệu | PostgreSQL (EF Core + Npgsql 8.x) |
| Cache | Redis (StackExchange.Redis 2.x) |
| Message queue | RabbitMQ (MassTransit 8.x) |
| Frontend | JavaScript thuần (SPA), font Bricolage Grotesque + Manrope |
| Xác thực | JWT Bearer + Refresh Token (BCrypt) |
| Realtime | SignalR |
| Báo cáo PDF | DinkToPdf |
| Logging | Serilog → Loki |
| Metrics | Prometheus + Grafana |
| Container | Docker Compose + Nginx reverse proxy |

---

## 4. Hướng dẫn sử dụng

### 4.1 Vai trò người dùng

| Vai trò | Mô tả |
|---|---|
| **Admin** | Quản trị toàn bộ hệ thống: người dùng, tổ chức, phân quyền, xem audit log |
| **SecurityEngineer** | Tạo và chạy quét, xem và xuất báo cáo, quản lý findings |
| **Viewer** | Chỉ đọc: xem kết quả scan và báo cáo, không thể tạo scan mới |

### 4.2 Luồng sử dụng cơ bản

#### Bước 1 — Đăng ký / Đăng nhập

1. Truy cập Security Portal qua trình duyệt.
2. Đăng ký tài khoản mới: điền email, tên đăng nhập, mật khẩu và tên tổ chức.
3. Đăng nhập nhận JWT token; token được làm mới tự động khi hết hạn.

#### Bước 2 — Cấu hình scan (tùy chọn)

1. Mở menu **Chức năng → Cấu hình**.
2. Tích chọn các **Security Checks** muốn thực hiện.
3. Chọn **Tools** bên ngoài sẽ được sử dụng (Naabu, Nuclei, Feroxbuster, v.v.).
4. Chọn loại **Báo cáo** (Technical / Executive / OWASP).
5. Cấu hình được lưu tự động và áp dụng cho mọi lần quét tiếp theo.

#### Bước 3 — Quét bảo mật

1. Ở trang chủ, nhập địa chỉ website cần quét (ví dụ: `https://example.com`).
2. Bật **"Scan với đăng nhập"** nếu cần quét khu vực sau đăng nhập — điền `Login URL`, `Username`, `Password` và loại xác thực (Form / HTTP Basic / GraphQL).
3. Nhấn **Bắt đầu scan**.
4. Theo dõi tiến trình thời gian thực trực tiếp trên giao diện.
5. Nhấn **Dừng scan** nếu muốn hủy giữa chừng.

#### Bước 4 — Đọc Security Report

Báo cáo hiển thị ngay sau khi scan hoàn tất, gồm:

- **Chỉ số tổng quan**: HTTP status, thời gian phản hồi, HTTPS, Server header.
- **Điểm rủi ro**: thanh màu từ xanh (an toàn) đến đỏ (rủi ro cao).
- **Executive Summary**: tóm tắt bằng ngôn ngữ tự nhiên.
- **Bảng Findings**: mỗi dòng là một lỗ hổng/cấu hình sai với mức độ, công cụ phát hiện, khuyến nghị và các bước tái hiện.
- Nút **Export Report** để xuất PDF.

#### Bước 5 — Xem lại lịch sử

1. Mở **Chức năng → Lịch sử**.
2. Danh sách các lượt quét hiển thị theo thứ tự thời gian.
3. Nhấn vào một lượt quét để xem lại báo cáo đầy đủ.
4. Tích chọn nhiều bản ghi rồi **Xóa** để dọn dẹp lịch sử.

### 4.3 Tính năng quét có xác thực (Authenticated Scan)

Security Portal hỗ trợ quét vào vùng sau đăng nhập với 3 loại:

| Loại | Khi nào dùng |
|---|---|
| **Form login** | Website có form username/password thông thường |
| **HTTP Basic** | API hoặc trang bảo vệ bằng HTTP Basic Authentication |
| **GraphQL API** | Ứng dụng dùng GraphQL — trỏ tới endpoint `/graphql` |

> Trường **Clinic / Hospital ID** khả dụng cho hệ thống y tế yêu cầu thêm định danh cơ sở.

---

## 5. Bảo mật và quyền riêng tư

- Mật khẩu người dùng được băm bằng **BCrypt** — không lưu plaintext.
- JWT token có thời hạn ngắn; Refresh Token được quản lý server-side và có thể thu hồi.
- Mọi thao tác quan trọng được ghi **Audit Log** kèm IP, UserAgent và dữ liệu thay đổi.
- Thông tin xác thực scan (password, clinic ID) chỉ lưu trong cấu hình scan; API trả về dữ liệu đã che (`UsernameMasked`, `ClinicIdMasked`) — không bao giờ trả về plaintext.
- Giao tiếp giữa frontend và API qua Nginx reverse proxy (HTTPS).

---

## 6. Triển khai

Hệ thống triển khai hoàn toàn bằng **Docker Compose**:

```bash
# Khởi động toàn bộ stack
docker compose up -d

# Xem log
docker compose logs -f
```

Các service chạy trong Docker:

| Service | Vai trò |
|---|---|
| `nginx` | Reverse proxy, phục vụ frontend |
| `api` | SecurityPortal.API (.NET 8) |
| `postgres` | Cơ sở dữ liệu chính |
| `redis` | Cache |
| `rabbitmq` | Message queue |
| `prometheus` | Thu thập metrics |
| `grafana` | Dashboard giám sát |
| Workers | Các worker quét chạy song song |

---

## 7. API Reference

Tài liệu API tự động được tạo bằng Swagger/OpenAPI, truy cập tại:

```
http://localhost:<port>/swagger
```

API hỗ trợ versioning theo URL (`/api/v1/...`). Xác thực bằng JWT Bearer token — thêm header:

```
Authorization: Bearer <token>
```

---

*Tài liệu này mô tả phiên bản Security Portal hiện tại. Một số tính năng (AI Service, Project Management, Asset Management) đang trong quá trình phát triển.*
