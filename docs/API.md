# API 文档（v1）

Base URL: `http://localhost:8080/api/v1`

## 0. Swagger 文档

- Swagger UI：`http://localhost:8080/docs`
- OpenAPI JSON：`http://localhost:8080/api/v1/openapi.json`

说明：OpenAPI 由后端路由注册表自动生成，代码中的 API 路由变化后会自动映射到最新文档。

统一响应格式：

- 成功：
```json
{"success":true,"data":{}}
```

- 失败：
```json
{"success":false,"error":{"code":"ERROR_CODE","message":"错误描述"}}
```

## 1. 健康检查

### GET `/health`

返回服务状态。

## 2. 认证

### POST `/auth/register`

创建用户。

- 当系统中没有任何用户时：允许匿名调用，首个用户强制为 `admin`
- 当系统已有用户时：必须由 `admin` 调用

请求体：

```json
{
  "username": "admin",
  "password": "Admin@123456",
  "role": "admin",
  "full_name": "张三",
  "email": "admin@example.com",
  "phone": "13800000000"
}
```

### POST `/auth/login`

登录并获取 Token。

请求体：

```json
{
  "username": "admin",
  "password": "Admin@123456"
}
```

返回示例：

```json
{
  "success": true,
  "data": {
    "access_token": "xxxxx",
    "token_type": "Bearer",
    "expires_at": 1730000000,
    "user_id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

### POST `/auth/logout`

退出登录，需 Header：

```http
Authorization: Bearer <token>
```

### GET `/auth/me`

获取当前登录用户信息（包含解密后的用户字段）。

## 3. 商品管理

### POST `/products`

新增商品（仅 admin）。

请求体：

```json
{
  "sku": "WATER-550ML",
  "name": "矿泉水 550ml",
  "unit": "瓶"
}
```

### GET `/products`

获取商品列表。

## 4. 进销存

### POST `/inbound`

入库（采购补货）。可指定柜机编号，同时更新柜机级库存。

请求体：

```json
{
  "sku": "WATER-550ML",
  "quantity": 100,
  "unit_cost_cents": 120,
  "note": "周一补货",
  "device_code": "DEV-COLD-001"
}
```

字段说明：
- `device_code`（可选）：入库到指定柜机，同时增加该柜机的 `cabinet_quantity`

### POST `/sales`

销售出库。需指定柜机编号，检查温度暂停状态和柜机库存。

请求体：

```json
{
  "sku": "WATER-550ML",
  "quantity": 5,
  "unit_price_cents": 200,
  "note": "扫码售卖",
  "device_code": "DEV-COLD-001"
}
```

字段说明：
- `device_code`（可选，建议必填）：从指定柜机出库

错误码：
- `INSUFFICIENT_STOCK`：商品全局库存不足（409）
- `INSUFFICIENT_CABINET_STOCK`：柜机级库存不足（409）
- `DEVICE_SUSPENDED`：设备温度超限，暂停售卖，无法出库（409）

### GET `/inventory`

获取库存汇总与明细。

### GET `/movements?type=IN&limit=50`

获取库存流水。

- `type`: 可选，`IN` 或 `OUT`
- `limit`: 可选，范围 `1~200`，默认 `50`

## 5. 温度管控

### 设备类型与温度区间

| 类型 | 说明 | 建议温度区间 |
|------|------|-------------|
| `COLD` | 冷藏柜 | 2°C ~ 8°C |
| `NORMAL` | 常温柜 | 10°C ~ 30°C |
| `HOT` | 加热柜 | 55°C ~ 65°C |

### POST `/devices`

创建设备（仅 admin）。

请求体：

```json
{
  "code": "DEV-COLD-001",
  "name": "冷藏柜1号",
  "device_type": "COLD",
  "min_temp_c": 2.0,
  "max_temp_c": 8.0
}
```

### GET `/devices`

查询所有设备列表（公开）。

返回字段：
- `id`, `code`, `name`, `device_type`
- `min_temp_c`, `max_temp_c`, `current_temp_c`
- `is_suspended`：是否因温度超限暂停售卖（0/1）
- `created_at`, `updated_at`

### POST `/devices/temperature`

上报设备温度，自动检测超限并触发/解除告警。

请求体：

```json
{
  "code": "DEV-COLD-001",
  "temperature_c": 5.0
}
```

返回字段：
- `temperature_c`, `min_temp_c`, `max_temp_c`
- `temperature_status`：`NORMAL` / `OVERHEAT` / `UNDERHEAT`
- `is_out_of_range`：是否超出温度区间（true/false）
- `is_suspended`：设备是否暂停售卖（true/false，真实从DB读取）
- `alert_triggered`：本次上报是否新触发了告警
- `alert_resolved`：本次上报是否解除了活动告警
- `alert_type`：触发告警时的类型 `OVERHEAT`/`UNDERHEAT`

自动处理逻辑：
- 温度首次超出区间：创建活动告警记录 + 标记设备 `is_suspended=1`
- 温度恢复正常区间：关闭告警（写入 `end_time`、`end_temp_c`）+ 恢复设备售卖

### POST `/devices/products`

给设备添加商品关联（仅 admin）。

请求体：

```json
{
  "device_code": "DEV-COLD-001",
  "sku": "WATER-550ML"
}
```

### DELETE `/devices/products`

移除设备商品关联（仅 admin）。

请求体：

```json
{
  "device_code": "DEV-COLD-001",
  "sku": "WATER-550ML"
}
```

### GET `/devices/status?code=DEV-COLD-001`

**补货员核心接口**：查询设备状态，明确哪些商品可以继续卖。

Query 参数：
- `code`（必填）：设备编号

返回结构示例：

```json
{
  "success": true,
  "data": {
    "id": 1,
    "code": "DEV-COLD-001",
    "name": "冷藏柜1号",
    "device_type": "COLD",
    "min_temp_c": 2.0,
    "max_temp_c": 8.0,
    "current_temp_c": 10.5,
    "temperature_status": "OVERHEAT",
    "is_out_of_range": true,
    "is_suspended": true,
    "summary": {
      "product_count": 3,
      "total_cabinet_quantity": 120,
      "sellable_product_count": 0,
      "unsellable_product_count": 3
    },
    "active_alert": {
      "id": 5,
      "alert_type": "OVERHEAT",
      "start_time": "2026-06-19 10:30:00",
      "start_temp_c": 10.5,
      "affected_products": ["WATER-550ML:矿泉水550ml"]
    },
    "products": [
      {
        "id": 1,
        "sku": "WATER-550ML",
        "name": "矿泉水550ml",
        "unit": "瓶",
        "stock_quantity": 50,
        "cabinet_quantity": 30,
        "can_sell": false,
        "unsellable_reason": "设备温度超限，暂停售卖"
      }
    ]
  }
}
```

商品级 `can_sell` 判断规则：
- `true`：设备未暂停 **且** 柜机库存 > 0
- `false`：设备暂停（`unsellable_reason=设备温度超限，暂停售卖`）
- `false`：柜机库存为 0（`unsellable_reason=柜机库存为0`）

### GET `/temperature/alerts?device_code=xxx&active_only=1&limit=50`

查询温度异常历史记录。

Query 参数：
- `device_code`（可选）：按设备编号过滤
- `active_only`（可选，`1`）：只返回活动中未恢复的告警
- `limit`（可选）：范围 `1~200`，默认 `50`

返回字段（每条记录）：
- `id`, `device_code`, `device_name`, `alert_type`
- `start_time`：超限开始时间
- `end_time`：恢复时间（活动告警为 null）
- `is_active`：是否仍在活动中
- `start_temp_c`, `end_temp_c`
- `affected_products`：受影响商品列表（JSON数组）
- `note`, `created_at`

## 6. cURL 示例

```bash
# 1) 管理员注册
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123456","full_name":"管理员","email":"admin@park.com","phone":"13800000000"}'

# 2) 登录
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123456"}' | jq -r '.data.access_token')

# 3) 新增商品
curl -X POST http://localhost:8080/api/v1/products \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"WATER-550ML","name":"矿泉水550ml","unit":"瓶"}'

# 4) 入库（指定柜机，同时更新柜机库存）
curl -X POST http://localhost:8080/api/v1/inbound \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"WATER-550ML","quantity":200,"unit_cost_cents":100,"device_code":"DEV-COLD-001"}'

# 5) 销售出库（指定柜机，自动检查温度状态与柜机库存）
curl -X POST http://localhost:8080/api/v1/sales \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sku":"WATER-550ML","quantity":8,"unit_price_cents":200,"device_code":"DEV-COLD-001"}'

# 6) 查看库存
curl http://localhost:8080/api/v1/inventory

# ========== 温度管控 ==========

# 7) 查询设备列表
curl http://localhost:8080/api/v1/devices

# 8) 上报正常温度
curl -X POST http://localhost:8080/api/v1/devices/temperature \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"code":"DEV-COLD-001","temperature_c":5.0}'

# 9) 上报过热温度（触发告警 + 自动暂停售卖）
curl -X POST http://localhost:8080/api/v1/devices/temperature \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"code":"DEV-COLD-001","temperature_c":12.0}'

# 10) 温度恢复正常（自动解除告警 + 恢复售卖）
curl -X POST http://localhost:8080/api/v1/devices/temperature \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"code":"DEV-COLD-001","temperature_c":4.5}'

# 11) 给设备添加商品
curl -X POST http://localhost:8080/api/v1/devices/products \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"device_code":"DEV-COLD-001","sku":"WATER-550ML"}'

# 12) 补货员查询设备状态（核心接口，查看不可售卖商品）
curl -X GET "http://localhost:8080/api/v1/devices/status?code=DEV-COLD-001" \
  -H "Authorization: Bearer $TOKEN"

# 13) 查询温度异常记录（仅活动告警）
curl -X GET "http://localhost:8080/api/v1/temperature/alerts?active_only=1&limit=20" \
  -H "Authorization: Bearer $TOKEN"

# 14) 查询指定设备的所有温度告警
curl -X GET "http://localhost:8080/api/v1/temperature/alerts?device_code=DEV-COLD-001" \
  -H "Authorization: Bearer $TOKEN"
```
