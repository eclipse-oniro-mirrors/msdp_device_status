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

#ifndef FEEDBACK_STORE_H
#define FEEDBACK_STORE_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "behavior_awareness_data.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "rdb_store.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {

constexpr const char *PERCEPTION_DB_PATH =
    "/data/service/el1/public/database/distributeddata/rdb/system_data/behavior_sequence/perception.db";
constexpr const char *PERCEPTION_DB_TABLE = "habit_perceptions";
constexpr int32_t PERCEPTION_DB_VERSION = 1;
constexpr int32_t INVALID_ID = 0;

struct FeedbackRecord {
    int64_t id { 0 };
    std::string perceptionEventId;
    int32_t feedbackType { 0 };
    int64_t feedbackTime { 0 };
    std::string feedbackJson;
    int64_t createdTime { 0 };
    int64_t updateTime { 0 };
};

class FeedbackStore {
public:
    static FeedbackStore &GetInstance();
    DISALLOW_COPY_AND_MOVE(FeedbackStore);
    ~FeedbackStore() = default;

    int32_t InsertFeedback(const FeedbackData &feedback);
    int32_t QueryFeedback(const std::string &perceptionEventId, FeedbackRecord &out);
    int32_t QueryAll(std::vector<FeedbackRecord> &out);
    void Clear();

    void SetDatabasePathForTesting(const std::string &path);

private:
    FeedbackStore();
    int32_t InitRdbStore();
    int32_t EnsureTable();
    int32_t SerializeFeedbackJson(int32_t feedbackType, int64_t feedbackTime, std::string &out);
    int32_t ParseFeedbackType(const std::string &feedbackJson);
    int64_t MapEventIdToId(const std::string &perceptionEventId);
    int32_t QueryFeedbackType(int64_t id, bool &recordFound, int32_t &outType);
    int32_t UpdateFeedbackField(int64_t id, const std::string &feedbackJson, int64_t updateTime);
    int32_t ProcessFeedback(int64_t id, const FeedbackData &feedback);

    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::mutex mtx_;
    bool inited_ { false };
    std::string databasePath_ { PERCEPTION_DB_PATH };
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // FEEDBACK_STORE_H
