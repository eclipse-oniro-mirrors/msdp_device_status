/**
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

#include <cstdlib>
#include <charconv>
#include <unistd.h>

#include "abs_result_set.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_store_config.h"
#include "transaction.h"
#include "value_object.h"
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
constexpr int32_t DB_VERSION = 1;
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

class FeedbackStoreCallback : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return rdbStore.ExecuteSql(CREATE_TABLE_SQL);
    }
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override
    {
        return NativeRdb::E_OK;
    }
};
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
    if (access(databasePath_.c_str(), F_OK) != 0) {
        FI_HILOGE("InitRdbStore: db file not exist, err:%{public}d, path:%{public}s",
            SERVICE_EXCEPTION, databasePath_.c_str());
        return SERVICE_EXCEPTION;
    }
    NativeRdb::RdbStoreConfig config(databasePath_);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    FeedbackStoreCallback callback;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(config, DB_VERSION, callback, errCode);
    if (rdbStore_ == nullptr || errCode != NativeRdb::E_OK) {
        FI_HILOGE("InitRdbStore: GetRdbStore failed, err:%{public}d, rdbErr:%{public}d",
            SERVICE_EXCEPTION, errCode);
        return SERVICE_EXCEPTION;
    }
    auto [trxErr, transaction] = rdbStore_->CreateTransaction(NativeRdb::Transaction::IMMEDIATE);
    if (trxErr != NativeRdb::E_OK || transaction == nullptr) {
        FI_HILOGE("InitRdbStore: CreateTransaction failed, err:%{public}d, rdbErr:%{public}d",
            SERVICE_EXCEPTION, trxErr);
        return SERVICE_EXCEPTION;
    }
    int32_t ret = EnsureTable(transaction);
    if (ret != RET_OK) {
        int32_t rollRet = transaction->Rollback();
        FI_HILOGE("InitRdbStore: EnsureTable failed, rollback:%{public}d, err:%{public}d",
            rollRet, SERVICE_EXCEPTION);
        return SERVICE_EXCEPTION;
    }
    int32_t commitRet = transaction->Commit();
    if (commitRet != NativeRdb::E_OK) {
        int32_t rollRet = transaction->Rollback();
        FI_HILOGE("InitRdbStore: Commit failed, rollback:%{public}d, rdbErr:%{public}d",
            rollRet, commitRet);
        return SERVICE_EXCEPTION;
    }
    inited_ = true;
    return RET_OK;
}

int32_t FeedbackStore::EnsureTable(const std::shared_ptr<NativeRdb::Transaction> &transaction)
{
    if (rdbStore_ == nullptr) {
        FI_HILOGE("EnsureTable: rdbStore_ is null, err:%{public}d", SERVICE_EXCEPTION);
        return SERVICE_EXCEPTION;
    }
    if (transaction == nullptr) {
        FI_HILOGE("EnsureTable: transaction is null, err:%{public}d", SERVICE_EXCEPTION);
        return SERVICE_EXCEPTION;
    }
    auto [errCode, value] = transaction->Execute(CREATE_TABLE_SQL);
    if (errCode != NativeRdb::E_OK) {
        FI_HILOGE("EnsureTable: Execute failed, err:%{public}d, rdbErr:%{public}d",
            SERVICE_EXCEPTION, errCode);
        return SERVICE_EXCEPTION;
    }
    return RET_OK;
}

int64_t FeedbackStore::MapEventIdToId(const std::string &perceptionEventId)
{
    size_t pos = perceptionEventId.find('_');
    if (pos == std::string::npos || pos + 1 >= perceptionEventId.length()) {
        return INVALID_ID;
    }
    std::string suffix = perceptionEventId.substr(pos + 1);
    int64_t result = 0;
    auto [ptr, ec] = std::from_chars(suffix.data(), suffix.data() + suffix.size(), result);
    if (ec != std::errc() || ptr != suffix.data() + suffix.size()) {
        FI_HILOGE("MapEventIdToId: parse failed, eventId:%{public}s, suffix:%{public}s",
            perceptionEventId.c_str(), suffix.c_str());
        return INVALID_ID;
    }
    return result;
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
    std::string numStr = feedbackJson.substr(pos);
    int32_t result = 0;
    auto [ptr, ec] = std::from_chars(numStr.data(), numStr.data() + numStr.size(), result);
    if (ec != std::errc()) {
        return -1;
    }
    return static_cast<int32_t>(result);
}

int32_t FeedbackStore::QueryFeedbackType(int64_t id, bool &recordFound, int32_t &outType)
{
    recordFound = false;
    outType = -1;
    if (rdbStore_ == nullptr) {
        FI_HILOGE("QueryFeedbackType: rdbStore_ null, err:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return SERVICE_EXCEPTION;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    std::vector<std::string> columns = { "feedback" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    if (resultSet == nullptr) {
        FI_HILOGE("QueryFeedbackType: Query null, err:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return SERVICE_EXCEPTION;
    }
    if (resultSet->GoToNextRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return RET_OK;
    }
    recordFound = true;
    std::string feedbackJson;
    int32_t ret = resultSet->GetString(0, feedbackJson);
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("QueryFeedbackType: GetString failed, err:%{public}d, rdbErr:%{public}d",
            SERVICE_EXCEPTION, ret);
        resultSet->Close();
        return SERVICE_EXCEPTION;
    }
    outType = ParseFeedbackType(feedbackJson);
    resultSet->Close();
    return RET_OK;
}

int32_t FeedbackStore::UpdateFeedbackField(int64_t id, const std::string &feedbackJson, int64_t updateTime)
{
    if (rdbStore_ == nullptr) {
        FI_HILOGE("UpdateFeedbackField: rdbStore_ null, err:%{public}d, id:%{public}" PRId64,
            SERVICE_EXCEPTION, id);
        return SERVICE_EXCEPTION;
    }
    NativeRdb::ValuesBucket values;
    values.PutString("feedback", feedbackJson);
    values.PutLong("update_time", updateTime);
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    int32_t changedRows = 0;
    int32_t ret = rdbStore_->Update(changedRows, values, predicates);
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("UpdateFeedbackField: Update failed, err:%{public}d, rdbErr:%{public}d, "
            "id:%{public}" PRId64 ", changed:%{public}d", SERVICE_EXCEPTION, ret, id, changedRows);
        return SERVICE_EXCEPTION;
    }
    return RET_OK;
}

int32_t FeedbackStore::ProcessFeedback(int64_t id, const FeedbackData &feedback)
{
    int32_t existingType = -1;
    bool recordFound = false;
    int32_t ret = QueryFeedbackType(id, recordFound, existingType);
    if (ret != RET_OK) {
        return SERVICE_EXCEPTION;
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
    if (ret != RET_OK) {
        return SERVICE_EXCEPTION;
    }
    FI_HILOGI("ProcessFeedback: updating, id:%{public}" PRId64 ", old:%{public}d, new:%{public}d",
        id, existingType, newType);
    ret = UpdateFeedbackField(id, feedbackJson, feedback.feedbackTime);
    if (ret != RET_OK) {
        return SERVICE_EXCEPTION;
    }
    return RET_OK;
}

int32_t FeedbackStore::InsertFeedback(const FeedbackData &feedback)
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (!inited_) {
        int32_t ret = InitRdbStore();
        if (ret != RET_OK || rdbStore_ == nullptr) {
            FI_HILOGE("InsertFeedback: init failed, err:%{public}d, eventId:%{public}s",
                SERVICE_EXCEPTION, feedback.perceptionEventId.c_str());
            return SERVICE_EXCEPTION;
        }
    }
    if (rdbStore_ == nullptr) {
        FI_HILOGE("InsertFeedback: rdbStore_ null, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, feedback.perceptionEventId.c_str());
        return SERVICE_EXCEPTION;
    }
    int64_t id = MapEventIdToId(feedback.perceptionEventId);
    if (id <= 0) {
        FI_HILOGE("InsertFeedback: invalid id, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, feedback.perceptionEventId.c_str());
        return SERVICE_EXCEPTION;
    }
    return ProcessFeedback(id, feedback);
}

int32_t FeedbackStore::QueryFeedback(const std::string &perceptionEventId, FeedbackRecord &out)
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (rdbStore_ == nullptr) {
        FI_HILOGE("QueryFeedback: rdbStore_ null, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, perceptionEventId.c_str());
        return SERVICE_EXCEPTION;
    }
    int64_t id = MapEventIdToId(perceptionEventId);
    if (id <= 0) {
        FI_HILOGE("QueryFeedback: invalid id, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, perceptionEventId.c_str());
        return SERVICE_EXCEPTION;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    predicates.EqualTo("id", std::to_string(id));
    std::vector<std::string> columns = { "id", "feedback", "created_time", "update_time" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    if (resultSet == nullptr) {
        FI_HILOGE("QueryFeedback: Query null, err:%{public}d, eventId:%{public}s",
            SERVICE_EXCEPTION, perceptionEventId.c_str());
        return SERVICE_EXCEPTION;
    }
    if (resultSet->GoToNextRow() != NativeRdb::E_OK) {
        resultSet->Close();
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
    resultSet->Close();
    return RET_OK;
}

int32_t FeedbackStore::QueryAll(std::vector<FeedbackRecord> &out)
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (rdbStore_ == nullptr) {
        FI_HILOGE("QueryAll: rdbStore_ null, err:%{public}d", SERVICE_EXCEPTION);
        return SERVICE_EXCEPTION;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    std::vector<std::string> columns = { "id", "feedback", "created_time", "update_time" };
    auto resultSet = rdbStore_->Query(predicates, columns);
    if (resultSet == nullptr) {
        FI_HILOGE("QueryAll: Query null, err:%{public}d", SERVICE_EXCEPTION);
        return SERVICE_EXCEPTION;
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
    resultSet->Close();
    return RET_OK;
}

void FeedbackStore::Clear()
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (rdbStore_ == nullptr) {
        FI_HILOGE("Clear: rdbStore_ null, err:%{public}d", SERVICE_EXCEPTION);
        return;
    }
    NativeRdb::RdbPredicates predicates(PERCEPTION_DB_TABLE);
    int32_t deletedRows = 0;
    int32_t ret = rdbStore_->Delete(deletedRows, predicates);
    if (ret != NativeRdb::E_OK) {
        FI_HILOGE("Clear: Delete failed, err:%{public}d, rdbErr:%{public}d",
            SERVICE_EXCEPTION, ret);
    }
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
