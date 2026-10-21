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
    // DD-8: The feedback interface only updates existing recommendation records.
    // It must not create a new database; the perception.db file is created by the
    // habit-perception generation stage. If the file is missing, log an error and
    // return RET_OK (fault-tolerance strategy, DD-7) so the caller's Promise resolves.
    if (access(databasePath_.c_str(), F_OK) != 0) {
        FI_HILOGE("Database file does not exist, path:%{public}s", databasePath_.c_str());
        return RET_OK;
    }
    NativeRdb::RdbStoreConfig config;
    config.SetPath(databasePath_);
    config.SetBundleName("msdp");
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, errCode);
    // Fault tolerance (DD-7): GetRdbStore failure is an internal service exception.
    // Return RET_OK instead of 32500001 so the caller's Promise resolves normally.
    if (rdbStore_ == nullptr || errCode != NativeRdb::E_OK) {
        FI_HILOGE("GetRdbStore failed, errCode:%{public}d, path:%{public}s", errCode, databasePath_.c_str());
        return RET_OK;
    }
    int32_t ret = EnsureTable();
    if (ret != RET_OK) {
        // Fault tolerance: EnsureTable failure is treated as a service exception (AC-1.5).
        return RET_OK;
    }
    inited_ = true;
    return RET_OK;
}

int32_t FeedbackStore::EnsureTable()
{
    // Fault tolerance (DD-7): null rdbStore_ means the database could not be opened.
    // Return RET_OK so the caller's Promise resolves without throwing 32500001.
    if (rdbStore_ == nullptr) {
        return RET_OK;
    }
    int32_t errCode = rdbStore_->ExecuteSql(CREATE_TABLE_SQL);
    // Fault tolerance (AC-1.5): DDL failure is an internal RDB I/O exception.
    // Log the error and return RET_OK; do not propagate 32500001 to the caller.
    if (errCode != NativeRdb::E_OK) {
        FI_HILOGE("EnsureTable failed, errCode:%{public}d", errCode);
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
    // Fault tolerance (DD-7): null rdbStore_ means the database is unavailable.
    // Return RET_OK with recordFound=false; the caller treats this as "record not found".
    if (rdbStore_ == nullptr) {
        return RET_OK;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    std::vector<std::string> columns = { "feedback" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    // Fault tolerance (AC-1.5): null result set indicates an RDB I/O failure.
    // Log the error and return RET_OK without throwing 32500001.
    if (resultSet == nullptr) {
        FI_HILOGE("QueryFeedbackType: Query returned null, id:%{public}" PRId64, id);
        return RET_OK;
    }
    // No matching row means the recommendation record does not exist (EX-6).
    // Return RET_OK with recordFound=false; caller will log WARN and skip INSERT.
    if (resultSet->GoToNextRow() != NativeRdb::E_OK) {
        return RET_OK;
    }
    recordFound = true;
    std::string feedbackJson;
    int32_t ret = resultSet->GetString(0, feedbackJson);
    // Fault tolerance (AC-1.5): column read failure is an RDB I/O exception.
    // Log the error and return RET_OK; outType stays -1 (unparseable).
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("QueryFeedbackType: GetString failed, ret:%{public}d, id:%{public}" PRId64, ret, id);
        return RET_OK;
    }
    outType = ParseFeedbackType(feedbackJson);
    return RET_OK;
}

int32_t FeedbackStore::UpdateFeedbackField(int64_t id, const std::string &feedbackJson, int64_t updateTime)
{
    // Fault tolerance (DD-7): null rdbStore_ means the database is unavailable.
    // Return RET_OK so the caller's Promise resolves without throwing 32500001.
    if (rdbStore_ == nullptr) {
        return RET_OK;
    }
    NativeRdb::ValuesBucket values;
    values.PutString("feedback", feedbackJson);
    values.PutLong("update_time", updateTime);
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    int32_t changedRows = 0;
    int32_t ret = rdbStore_->Update(changedRows, values, predicates);
    // Fault tolerance (AC-1.5): UPDATE failure is an RDB I/O exception.
    // Log the error code and return RET_OK; do not propagate 32500001 to the caller.
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("UpdateFeedbackField failed, id:%{public}" PRId64 ", rdbErrCode:%{public}d, changedRows:%{public}d",
            id, ret, changedRows);
        return RET_OK;
    }
    return RET_OK;
}

int32_t FeedbackStore::InsertFeedback(const FeedbackData &feedback)
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (!inited_) {
        int32_t ret = InitRdbStore();
        // Fault tolerance (AC-1.5): InitRdbStore may fail to open the database
        // (file missing, RDB I/O error). Return RET_OK so the caller's Promise
        // resolves without throwing 32500001 to the voice-assistant service.
        if (ret != RET_OK || rdbStore_ == nullptr) {
            return RET_OK;
        }
    }
    // Fault tolerance (DD-7): rdbStore_ is null when the database is unavailable.
    // Log the error and return RET_OK; the feedback data is simply not persisted.
    if (rdbStore_ == nullptr) {
        FI_HILOGE("InsertFeedback: rdbStore_ is null, eventId:%{public}s",
            feedback.perceptionEventId.c_str());
        return RET_OK;
    }
    int64_t id = MapEventIdToId(feedback.perceptionEventId);
    // Invalid id mapping is a defensive check; ValidateFeedback should have caught
    // this earlier (returns 401). If we reach here with id <= 0, treat as a
    // fault-tolerance case and return RET_OK without writing.
    if (id <= 0) {
        FI_HILOGE("InsertFeedback: invalid id mapping, eventId:%{public}s, id:%{public}" PRId64,
            feedback.perceptionEventId.c_str(), id);
        return RET_OK;
    }
    int32_t existingType = -1;
    bool recordFound = false;
    int32_t ret = QueryFeedbackType(id, recordFound, existingType);
    // Fault tolerance (AC-1.5): QueryFeedbackType failure is an RDB I/O exception.
    // Return RET_OK without throwing 32500001 to the caller.
    if (ret != RET_OK) {
        return RET_OK;
    }
    // EX-6: The recommendation record does not exist in habit_perceptions.
    // The feedback interface only updates existing records; it must not INSERT
    // new ones. Log a WARN and return RET_OK (normal return, no data written).
    if (!recordFound) {
        FI_HILOGW("InsertFeedback: habit_perceptions record not found, eventId:%{public}s, id:%{public}" PRId64,
            feedback.perceptionEventId.c_str(), id);
        return RET_OK;
    }
    int32_t newType = static_cast<int32_t>(feedback.feedbackType);
    // EX-7 / DD-2: Idempotent case — same perceptionEventId + same feedbackType.
    // Return RET_OK without repeating the UPDATE to avoid duplicate data points.
    if (existingType >= 0 && existingType == newType) {
        FI_HILOGI("InsertFeedback: idempotent hit, eventId:%{public}s, id:%{public}" PRId64,
            feedback.perceptionEventId.c_str(), id);
        return RET_OK;
    }
    std::string feedbackJson;
    ret = SerializeFeedbackJson(newType, feedback.feedbackTime, feedbackJson);
    // Fault tolerance (EX-4): JSON serialization failure is a data-processing
    // exception. Return RET_OK without throwing 32500001 (not an independent AC).
    if (ret != RET_OK) {
        return RET_OK;
    }
    FI_HILOGI("InsertFeedback: updating feedback, eventId:%{public}s, id:%{public}" PRId64
        ", oldType:%{public}d, newType:%{public}d",
        feedback.perceptionEventId.c_str(), id, existingType, newType);
    ret = UpdateFeedbackField(id, feedbackJson, feedback.feedbackTime);
    // Fault tolerance (AC-1.5): UpdateFeedbackField failure is an RDB I/O exception.
    // The internal HILOG_ERROR already records the RDB error code and reason.
    // Return RET_OK so the caller's Promise resolves without throwing 32500001.
    if (ret != RET_OK) {
        return RET_OK;
    }
    return RET_OK;
}

int32_t FeedbackStore::QueryFeedback(const std::string &perceptionEventId, FeedbackRecord &out)
{
    std::lock_guard<std::mutex> lock(mtx_);
    // Fault tolerance (DD-7): null rdbStore_ means the database is unavailable.
    // Return RET_OK with an empty record; the caller checks the record fields.
    if (rdbStore_ == nullptr) {
        return RET_OK;
    }
    int64_t id = MapEventIdToId(perceptionEventId);
    if (id <= 0) {
        return RET_OK;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    std::vector<std::string> columns = { "id", "feedback", "created_time", "update_time" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    // Fault tolerance (AC-1.5): null result set indicates an RDB I/O failure.
    if (resultSet == nullptr) {
        return RET_OK;
    }
    // No matching row means the recommendation record does not exist.
    if (resultSet->GoToNextRow() != NativeRdb::E_OK) {
        return RET_OK;
    }
    out.perceptionEventId = perceptionEventId;
    out.id = id;
    std::string feedbackJson;
    int32_t ret = resultSet->GetString(1, feedbackJson);
    if (ret == NativeRdb::E_OK) {
        out.feedbackJson = feedbackJson;
        out.feedbackType = ParseFeedbackType(feedbackJson);
    }
    int64_t createdTime = 0;
    ret = resultSet->GetLong(2, createdTime);
    if (ret == NativeRdb::E_OK) {
        out.createdTime = createdTime;
    }
    int64_t updateTime = 0;
    ret = resultSet->GetLong(3, updateTime);
    if (ret == NativeRdb::E_OK) {
        out.updateTime = updateTime;
    }
    return RET_OK;
}

int32_t FeedbackStore::QueryAll(std::vector<FeedbackRecord> &out)
{
    std::lock_guard<std::mutex> lock(mtx_);
    // Fault tolerance (DD-7): null rdbStore_ means the database is unavailable.
    // Return RET_OK with an empty result vector.
    if (rdbStore_ == nullptr) {
        return RET_OK;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    std::vector<std::string> columns = { "id", "feedback", "created_time", "update_time" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    // Fault tolerance (AC-1.5): null result set indicates an RDB I/O failure.
    if (resultSet == nullptr) {
        return RET_OK;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FeedbackRecord record;
        int64_t id = 0;
        int32_t ret = resultSet->GetLong(0, id);
        if (ret != NativeRdb::E_OK) {
            continue;
        }
        record.id = id;
        std::string feedbackJson;
        ret = resultSet->GetString(1, feedbackJson);
        if (ret == NativeRdb::E_OK) {
            record.feedbackJson = feedbackJson;
            record.feedbackType = ParseFeedbackType(feedbackJson);
        }
        int64_t createdTime = 0;
        ret = resultSet->GetLong(2, createdTime);
        if (ret == NativeRdb::E_OK) {
            record.createdTime = createdTime;
        }
        int64_t updateTime = 0;
        ret = resultSet->GetLong(3, updateTime);
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
    // Fault tolerance (DD-7): null rdbStore_ means the database is unavailable.
    // Simply return; nothing to clear.
    if (rdbStore_ == nullptr) {
        return;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    int32_t deletedRows = 0;
    int32_t ret = rdbStore_->Delete(deletedRows, predicates);
    // Fault tolerance (AC-1.5): DELETE failure is an RDB I/O exception.
    // Log the error code; this method is test-only and does not propagate errors.
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("Clear failed, rdbErrCode:%{public}d", ret);
    }
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
