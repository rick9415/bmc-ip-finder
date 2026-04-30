# BMC 2600 IP Finder

區域網路 BMC 設備自動掃描工具，透過瀏覽器介面即時顯示在線主機、IPMI 狀態與 Redfish 硬體資訊。

## 功能

- **自動掃描** — 開啟頁面即自動偵測本機子網路並開始掃描
- **BMC 候選識別** — 依 IPMI (UDP 623)、HTTP/HTTPS + SSH 開放情況判斷是否為 BMC
- **Redfish 查詢** — 取得系統製造商、型號、序號、電源狀態、BIOS 版本、CPU、記憶體、BMC 韌體等
- **ARP + 反解 DNS** — 顯示 MAC 位址與主機名稱
- **即時進度** — 掃描與 Redfish 查詢均有進度條
- **篩選排序** — 依 IP / MAC / 主機名 排序，可切換「全部 / 僅 BMC / 有 Redfish」

## 快速開始

### 需求

- Python 3.10+
- Windows / Linux（無需額外安裝套件，僅使用標準函式庫）

### 啟動

**Windows（雙擊）**

```
IpFinder.bat
```

**手動**

```bash
python app.py
```

伺服器啟動後開啟瀏覽器前往 `http://localhost:5000`，頁面載入即自動開始掃描。

## 使用說明

### 網路掃描

頁面開啟後自動掃描偵測到的本機子網路。若需指定範圍，在輸入框填入 CIDR（如 `192.168.10.0/24`）後點擊「開始掃描」。

### Redfish 查詢

掃描完成後，輸入 BMC 帳號密碼，點擊「Redfish 查詢全部 BMC」即可批次取得硬體詳情。點擊任一列可展開 Redfish 詳細資料。

### 快速連結

表格內提供 HTTP / HTTPS / SSH 連結，可直接跳轉至 BMC 管理介面。

## 檔案結構

```
.
├── app.py        # HTTP 伺服器 + API 路由
├── scanner.py    # 掃描邏輯（ping、port check、ARP、Redfish）
├── index.html    # 前端介面
└── IpFinder.bat  # Windows 一鍵啟動
```

## API

| 路徑 | 說明 |
|------|------|
| `GET /api/subnets` | 取得本機偵測到的子網路 |
| `GET /api/start[?subnet=]` | 開始掃描（可選指定子網路） |
| `GET /api/stop` | 停止掃描 |
| `GET /api/status` | 取得掃描狀態與結果 |
| `GET /api/redfish_fetch?user=&pass=[&ip=]` | 批次或單台 Redfish 查詢 |
| `GET /api/redfish_status` | 取得 Redfish 查詢進度 |

## 注意事項

- 僅供內部網路管理使用
- Redfish 查詢會忽略自簽憑證（`CERT_NONE`），請勿用於不受信任的網路環境
- 掃描使用最多 128 個執行緒，大型子網路（/16）耗時較長
