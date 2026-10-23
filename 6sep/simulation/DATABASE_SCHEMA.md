# SQLite Database Schema: sentinel.db

**Database File**: `sentinel_db` (pulled from Android application package `com.sentinel.ai`)  
**ORM / Data Layer**: Android Jetpack Room Persistence Library v2.6+  
**Database Identity Hash**: `63f4a6173234feddb8edcd980214d396`  
**Locale**: `en_GB`  
**Page Size**: 4,096 bytes  
**Total Allocated Pages**: 32 (131,072 bytes)  

---

## 1. Table Architecture

### 1.1 `threat_records` (Primary Operational Ledger)
Stores all on-device threat evaluations, scans, and user threat event history.

```sql
CREATE TABLE `threat_records` (
    `id` TEXT NOT NULL,
    `recordType` TEXT NOT NULL,
    `source` TEXT NOT NULL,
    `senderDisplayName` TEXT,
    `senderIdentifier` TEXT,
    `content` TEXT,
    `riskLevel` TEXT NOT NULL,
    `riskScore` REAL NOT NULL,
    `explanation` TEXT NOT NULL,
    `recommendation` TEXT,
    `timestamp` INTEGER NOT NULL,
    PRIMARY KEY(`id`, `recordType`)
);
```

#### Columns
| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `NO` | Unique Evaluation UUID (UUIDv4/UUIDv5, 36 chars) |
| `recordType` | `TEXT` | `NO` | Entry discriminant: `SCAN_RESULT` or `THREAT` |
| `source` | `TEXT` | `NO` | Originating package or entry point (`com.whatsapp`, `com.google.android.apps.messaging`, `Intent (Link)`, `com.google.android.gm`) |
| `senderDisplayName` | `TEXT` | `YES` | Notification title, group sender, or contact display string |
| `senderIdentifier` | `TEXT` | `YES` | Phone number or sender identity handle (often NULL in group notifications) |
| `content` | `TEXT` | `YES` | Evaluated message body, notification text, or intercepted URL |
| `riskLevel` | `TEXT` | `NO` | Authoritative risk categorization: `GREEN`, `YELLOW`, `RED`, `CRITICAL` |
| `riskScore` | `REAL` | `NO` | Composite risk score output from `RiskFusionEngine` ($0.0 - 100.0$) |
| `explanation` | `TEXT` | `NO` | User-facing rationale and ML model attribution text |
| `recommendation` | `TEXT` | `YES` | Actionable safety recommendation guidance |
| `timestamp` | `INTEGER` | `NO` | Epoch millisecond timestamp of evaluation |

#### Indexes
* `sqlite_autoindex_threat_records_1` on `(`id`, `recordType`)` (Primary Key constraint)

---

### 1.2 `room_master_table` (Room Metadata)
```sql
CREATE TABLE room_master_table (
    id INTEGER PRIMARY KEY,
    identity_hash TEXT
);
```
* **Identity Row**: `(42, '63f4a6173234feddb8edcd980214d396')`

---

### 1.3 `android_metadata` (Android System Table)
```sql
CREATE TABLE android_metadata (
    locale TEXT
);
```
* **Locale Row**: `('en_GB')`
