# mireage-sentinel Web Design

本專案為 **mireage-sentinel 專案的網頁設計前端**，主要提供監控儀表板介面與資料視覺化。

## 專案聲明

- 設計與編寫者：**muxiang**
- 本網頁僅為**個人設計與編寫**
- 本專案本身不產生攻擊資料，僅負責前端展示與代理請求

## 啟用條件

前端要有資料顯示，必須先啟用原本主專案的 API：

1. 在原專案中先執行 `main.py` 啟動後端 API
2. 確認後端 API 可用（預設會由本專案代理到 `http://localhost:8000/api/v1/dashboard`）
3. 再啟動本前端專案

若未先啟動原專案 `main.py`，此網頁會正常開啟，但不會有即時資料。

## 目前目錄與路徑

```text
Mirage-Sentinel-Web/
├── index.html
├── main.js
├── style.css
├── server.js
├── package.json
└── README.md
```

## 環境需求

- Node.js 18+

## 安裝與執行

```bash
npm install
npm start
```

啟動後開啟：`http://localhost:3000`

## 可調整的環境變數

- `PORT`：前端 proxy server 連接埠（預設 `3000`）
- `BACKEND_API_BASE_URL`：後端 API 基底 URL（預設 `http://localhost:8000/api/v1/dashboard`）
- `API_KEY`：後端 API key（若後端啟用金鑰驗證）
