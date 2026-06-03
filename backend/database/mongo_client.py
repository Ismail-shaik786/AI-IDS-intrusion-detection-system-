"""
MongoDB persistent storage for IDS alerts.
Falls back gracefully if MongoDB is not running.
"""
import time
from datetime import datetime

try:
    from pymongo import MongoClient, DESCENDING
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False

_client = None
_db = None
_col = None

def get_collection():
    global _client, _db, _col
    if not MONGO_AVAILABLE:
        return None
    if _col is None:
        try:
            _client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
            _client.server_info()
            _db = _client["sentinelx"]
            _col = _db["alerts"]
            _col.create_index([("timestamp", DESCENDING)])
            _col.create_index([("src_ip", 1)])
            _col.create_index([("attack_type", 1)])
            _col.create_index([("severity", 1)])
            print("[MongoDB] Connected successfully to sentinelx.alerts")
        except Exception as e:
            print(f"[MongoDB] Not available: {e} — running in CSV-only mode")
            _col = None
    return _col


def insert_alert(data: dict):
    col = get_collection()
    if col is None:
        return None
    try:
        doc = {**data, "created_at": datetime.utcnow()}
        result = col.insert_one(doc)
        return str(result.inserted_id)
    except Exception as e:
        print(f"[MongoDB] Insert error: {e}")
        return None


def get_alerts(limit=100, skip=0, filters: dict = None):
    col = get_collection()
    if col is None:
        return []
    try:
        query = filters or {}
        cursor = col.find(query, {"_id": 0}).sort("timestamp", DESCENDING).skip(skip).limit(limit)
        return list(cursor)
    except Exception as e:
        print(f"[MongoDB] Query error: {e}")
        return []


def get_stats():
    col = get_collection()
    if col is None:
        return {}
    try:
        pipeline_total = col.count_documents({})
        pipeline_by_type = list(col.aggregate([
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]))
        pipeline_by_severity = list(col.aggregate([
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]))
        pipeline_top_ips = list(col.aggregate([
            {"$match": {"attack_type": {"$ne": "BENIGN"}}},
            {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]))
        return {
            "total": pipeline_total,
            "by_type": {d["_id"]: d["count"] for d in pipeline_by_type},
            "by_severity": {d["_id"]: d["count"] for d in pipeline_by_severity},
            "top_ips": [{"ip": d["_id"], "count": d["count"]} for d in pipeline_top_ips]
        }
    except Exception as e:
        print(f"[MongoDB] Stats error: {e}")
        return {}


def get_timeline(hours=24):
    col = get_collection()
    if col is None:
        return []
    try:
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(hours=hours)
        pipeline = [
            {"$match": {"created_at": {"$gte": since}}},
            {"$group": {
                "_id": {
                    "hour": {"$hour": "$created_at"},
                    "type": "$attack_type"
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.hour": 1}}
        ]
        return list(col.aggregate(pipeline))
    except Exception as e:
        print(f"[MongoDB] Timeline error: {e}")
        return []
