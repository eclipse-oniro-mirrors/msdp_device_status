/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "feedback_store.h"

#include <unistd.h>

#include "abs_result_set.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"
#include "values_bucket.h"

#undef LOG_TAG
#define LOG_TAG "FeedbackStore"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {

namespace {
constexpr const char *KEY_FEEDBACK_TYPE = "\"feedbackType\":";
constexpr int32_t COL_ID = 0;
constexpr int32_t COL_FEEDBACK = 1;
constexpr int32_t COL_CREATED_TIME = 2;
constexpr int32_t COL_UPDATE_TIME = 3;
constexpr const char *CREATE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS habit_perceptions ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "e TEXT NOT NULL, "
    "e_param TEXT DEFAULT '{}', "
    "a TEXT NOT NULL, "
    "a_param TEXT DEFAULT '{}', "
    "score REAL DEFAULT 0, "
    "confidence REAL DEFAULT 0, "
    "lift_degree REAL DEFAULT 0.9, "
    "novelty REAL DEFAULT 0.9, "
    "count INTEGER DEFAULT 0, "
    "pool TEXT DEFAULT 'general', "
    "perception_count INTEGER DEFAULT 0, "
    "feedback TEXT DEFAULT '{}', "
    "created_time INTEGER DEFAULT 0, "
    "update_time INTEGER DEFAULT 0)";
}

FeedbackStore &FeedbackStore::GetInstance()
{
    static FeedbackStore instance;
    return instance;
}

FeedbackStore::FeedbackStore() {}

void FeedbackStore::SetDatabasePathForTesting(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mtx_);
    databasePath_ = path;
    inited_ = false;
    rdbStore_.reset();
}

int32_t FeedbackStore::InitRdbStore()
{
    // DD-8: do not create a new database; return RET_OK if file is missing.
    if (access(databasePath_.c_str(), F_OK) != 0) {
        FI_HILOGE("InitRdbStore: database file does not exist, errCode:%{public}d, path:%{public}s",
            SERVICE_EXCEPTION, databasePath_.c_str());
        return RET_OK;
    }
    NativeRdb::RdbStoreConfig config;
    config.SetPath(databasePath_);
    config.SetBundleName("msdp");
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, errCode);
    // Fault tolerance: GetRdbStore failure returns RET_OK.
    if (rdbStore_ == nullptr || errCode != NativeRdb::E_OK) {
        FI_HILOGE("InitRdbStore: GetRdbStore failed, errCode:%{public}d, rdbErrCode:%{public}d, path:%{public}s",
            SERVICE_EXCEPTION, errCode, databasePath_.c_str());
        return RET_OK;
    }
    int32_t ret = EnsureTable();
    // Fault tolerance: EnsureTable failure returns RET_OK.
    if (ret != RET_OK) {
        FI_HILOGE("InitRdbStore: EnsureTable failed, errCode:%{public}d", SERVICE_EXCEPTION);
        return RET_OK;
    }
    inited_ = true;
    return RET_OK;
}

int32_t FeedbackStore::EnsureTable()
{
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("EnsureTable: rdbStore_ is null, errCode:%{public}d", SERVICE_EXCEPTION);
        return RET_OK;
    }
    int32_t errCode = rdbStore_->ExecuteSql(CREATE_TABLE_SQL);
    // Fault tolerance: DDL failure returns RET_OK.
    if (errCode != NativeRdb::E_OK) {
        FI_HILOGE("EnsureTable: ExecuteSql failed, errCode:%{public}d, rdbErrCode:%{public}d",
            SERVICE_EXCEPTION, errCode);
        return RET_OK;
    }
    return RET_OK;
}

int64_t FeedbackStore::MapEventIdToId(const std::string &perceptionEventId)
{
    size_t pos = perceptionEventId.find('_');
    if (pos == std::string::npos || pos + 1 >= perceptionEventId.length()) {
        return INVALID_ID;
    }
    try {
        return std::stoll(perceptionEventId.substr(pos + 1));
    } catch (const std::exception &e) {
        FI_HILOGE("MapEventIdToId: parse failed, eventId:%{public}s, reason:%{public}s",
            perceptionEventId.c_str(), e.what());
        return INVALID_ID;
    }
}

int32_t FeedbackStore::SerializeFeedbackJson(int32_t feedbackType, int64_t feedbackTime, std::string &out)
{
    out = "{\"feedbackType\":" + std::to_string(feedbackType) +
        ",\"feedbackTime\":" + std::to_string(feedbackTime) + "}";
    return RET_OK;
}

int32_t FeedbackStore::ParseFeedbackType(const std::string &feedbackJson)
{
    size_t pos = feedbackJson.find(KEY_FEEDBACK_TYPE);
    if (pos == std::string::npos) {
        return -1;
    }
    pos += std::char_traits<char>::length(KEY_FEEDBACK_TYPE);
    try {
        return std::stoi(feedbackJson.substr(pos));
    } catch (const std::exception &) {
        return -1;
    }
}

int32_t FeedbackStore::GenerateTaskId(const std::string &perceptionEventId, int64_t feedbackTime, std::string &out)
{
    out = perceptionEventId + "_" + std::to_string(feedbackTime);
    return RET_OK;
}

int32_t FeedbackStore::QueryFeedbackType(int64_t id, bool &recordFound, int32_t &outType)
{
    recordFound = false;
    outType = -1;
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("QueryFeedbackType: rdbStore_ is null, errCode:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return RET_OK;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    std::vector<std::string> columns = { "feedback" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    // Fault tolerance: Query returned null.
    if (resultSet == nullptr) {
        FI_HILOGE("QueryFeedbackType: Query returned null, errCode:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return RET_OK;
    }
    // No matching row — record does not exist (EX-6).
    if (resultSet->GoToNextRow() != NativeRdb::E_OK) {
        return RET_OK;
    }
    recordFound = true;
    std::string feedbackJson;
    int32_t ret = resultSet->GetString(0, feedbackJson);
    // Fault tolerance: column read failure.
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("QueryFeedbackType: GetString failed, errCode:%{public}d, rdbErrCode:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, ret, id);
        return RET_OK;
    }
    outType = ParseFeedbackType(feedbackJson);
    return RET_OK;
}

int32_t FeedbackStore::UpdateFeedbackField(int64_t id, const std::string &feedbackJson, int64_t updateTime)
{
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("UpdateFeedbackField: rdbStore_ is null, errCode:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return RET_OK;
    }
    NativeRdb::ValuesBucket values;
    values.PutString("feedback", feedbackJson);
    values.PutLong("update_time", updateTime);
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    int32_t changedRows = 0;
    int32_t ret = rdbStore_->Update(changedRows, values, predicates);
    // Fault tolerance: UPDATE failure returns RET_OK.
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("UpdateFeedbackField: Update failed, errCode:%{public}d, rdbErrCode:%{public}d, "
            "id:%{public}" PRId64 ", changedRows:%{public}d", SERVICE_EXCEPTION, ret, id, changedRows);
        return RET_OK;
    }
    return RET_OK;
}

int32_t FeedbackStore::ProcessFeedback(int64_t id, const FeedbackData &feedback)
{
    int32_t existingType = -1;
    bool recordFound = false;
    int32_t ret = QueryFeedbackType(id, recordFound, existingType);
    // Fault tolerance: QueryFeedbackType failed.
    if (ret != RET_OK) {
        FI_HILOGE("ProcessFeedback: query failed, err:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return RET_OK;
    }
    // EX-6: record not found, do not INSERT.
    if (!recordFound) {
        FI_HILOGW("ProcessFeedback: record not found, id:%{public}" PRId64, id);
        return RET_OK;
    }
    int32_t newType = static_cast<int32_t>(feedback.feedbackType);
    // EX-7: idempotent, skip UPDATE.
    if (existingType >= 0 && existingType == newType) {
        FI_HILOGI("ProcessFeedback: idempotent, id:%{public}" PRId64, id);
        return RET_OK;
    }
    std::string feedbackJson;
    ret = SerializeFeedbackJson(newType, feedback.feedbackTime, feedbackJson);
    // Fault tolerance: JSON serialization failed (EX-4).
    if (ret != RET_OK) {
        FI_HILOGE("ProcessFeedback: serialize failed, err:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return RET_OK;
    }
    FI_HILOGI("ProcessFeedback: updating, id:%{public}" PRId64 ", old:%{public}d, new:%{public}d",
        id, existingType, newType);
    ret = UpdateFeedbackField(id, feedbackJson, feedback.feedbackTime);
    // Fault tolerance: UpdateFeedbackField failed.
    if (ret != RET_OK) {
        FI_HILOGE("ProcessFeedback: update failed, err:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return RET_OK;
    }
    return RET_OK;
}

int32_t FeedbackStore::InsertFeedback(const FeedbackData &feedback)
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (!inited_) {
        int32_t ret = InitRdbStore();
        // Fault tolerance: InitRdbStore failed or rdbStore_ still null.
        if (ret != RET_OK || rdbStore_ == nullptr) {
            FI_HILOGE("InsertFeedback: init failed, err:%{public}d, eventId:%{public}s",
                SERVICE_EXCEPTION, feedback.perceptionEventId.c_str());
            return RET_OK;
        }
    }
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("InsertFeedback: rdbStore_ null, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, feedback.perceptionEventId.c_str());
        return RET_OK;
    }
    int64_t id = MapEventIdToId(feedback.perceptionEventId);
    // Defensive check: invalid id mapping.
    if (id <= 0) {
        FI_HILOGE("InsertFeedback: invalid id, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, feedback.perceptionEventId.c_str());
        return RET_OK;
    }
    return ProcessFeedback(id, feedback);
}

int32_t FeedbackStore::QueryFeedback(const std::string &perceptionEventId, FeedbackRecord &out)
{
    std::lock_guard<std::mutex> lock(mtx_);
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("QueryFeedback: rdbStore_ is null, errCode:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, perceptionEventId.c_str());
        return RET_OK;
    }
    int64_t id = MapEventIdToId(perceptionEventId);
    if (id <= 0) {
        FI_HILOGE("QueryFeedback: invalid id mapping, errCode:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, perceptionEventId.c_str());
        return RET_OK;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    std::vector<std::string> columns = { "id", "feedback", "created_time", "update_time" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    // Fault tolerance: Query returned null.
    if (resultSet == nullptr) {
        FI_HILOGE("QueryFeedback: Query returned null, errCode:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, perceptionEventId.c_str());
        return RET_OK;
    }
    // No matching row — record does not exist.
    if (resultSet->GoToNextRow() != NativeRdb::E_OK) {
        return RET_OK;
    }
    out.perceptionEventId = perceptionEventId;
    out.id = id;
    std::string feedbackJson;
    int32_t ret = resultSet->GetString(COL_FEEDBACK, feedbackJson);
    if (ret == NativeRdb::E_OK) {
        out.feedbackJson = feedbackJson;
        out.feedbackType = ParseFeedbackType(feedbackJson);
    }
    int64_t createdTime = 0;
    ret = resultSet->GetLong(COL_CREATED_TIME, createdTime);
    if (ret == NativeRdb::E_OK) {
        out.createdTime = createdTime;
    }
    int64_t updateTime = 0;
    ret = resultSet->GetLong(COL_UPDATE_TIME, updateTime);
    if (ret == NativeRdb::E_OK) {
        out.updateTime = updateTime;
    }
    return RET_OK;
}

int32_t FeedbackStore::QueryAll(std::vector<FeedbackRecord> &out)
{
    std::lock_guard<std::mutex> lock(mtx_);
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("QueryAll: rdbStore_ is null, errCode:%{public}d", SERVICE_EXCEPTION);
        return RET_OK;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    std::vector<std::string> columns = { "id", "feedback", "created_time", "update_time" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    // Fault tolerance: Query returned null.
    if (resultSet == nullptr) {
        FI_HILOGE("QueryAll: Query returned null, errCode:%{public}d", SERVICE_EXCEPTION);
        return RET_OK;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FeedbackRecord record;
        int64_t id = 0;
        int32_t ret = resultSet->GetLong(COL_ID, id);
        if (ret != NativeRdb::E_OK) {
            continue;
        }
        record.id = id;
        std::string feedbackJson;
        ret = resultSet->GetString(COL_FEEDBACK, feedbackJson);
        if (ret == NativeRdb::E_OK) {
            record.feedbackJson = feedbackJson;
            record.feedbackType = ParseFeedbackType(feedbackJson);
        }
        int64_t createdTime = 0;
        ret = resultSet->GetLong(COL_CREATED_TIME, createdTime);
        if (ret == NativeRdb::E_OK) {
            record.createdTime = createdTime;
        }
        int64_t updateTime = 0;
        ret = resultSet->GetLong(COL_UPDATE_TIME, updateTime);
        if (ret == NativeRdb::E_OK) {
            record.updateTime = updateTime;
        }
        out.push_back(record);
    }
    return RET_OK;
}

void FeedbackStore::Clear()
{
    std::lock_guard<std::mutex> lock(mtx_);
    // Fault tolerance: rdbStore_ is null.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("Clear: rdbStore_ is null, errCode:%{public}d", SERVICE_EXCEPTION);
        return;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    int32_t deletedRows = 0;
    int32_t ret = rdbStore_->Delete(deletedRows, predicates);
    // Fault tolerance: DELETE failure.
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("Clear: Delete failed, errCode:%{public}d, rdbErrCode:%{public}d", SERVICE_EXCEPTION, ret);
    }
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
