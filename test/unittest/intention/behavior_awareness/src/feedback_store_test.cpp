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

#include <gtest/gtest.h>
#include <unistd.h>

#include <string>

#include "abs_result_set.h"
#include "behavior_awareness_data.h"
#include "feedback_store.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"

#undef LOG_TAG
#define LOG_TAG "FeedbackStoreTest"

using namespace testing::ext;

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
namespace {
constexpr const char *TEST_DB_PATH = "/data/local/tmp/test_perception.db";
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

class FeedbackTestCallback : public NativeRdb::RdbOpenCallback {
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

void SetupTestDatabase(const std::string &path)
{
    unlink(path.c_str());
    NativeRdb::RdbStoreConfig config(path);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    FeedbackTestCallback callback;
    auto store = NativeRdb::RdbHelper::GetRdbStore(config, 1, callback, errCode);
    if (store == nullptr) {
        return;
    }
    store->ExecuteSql(
        "INSERT INTO habit_perceptions (id, e, a, feedback) VALUES (1, 'time', 'switch', '{}')");
    store->ExecuteSql(
        "INSERT INTO habit_perceptions (id, e, a, feedback) VALUES (2, 'time', 'switch', '{}')");
}
} // namespace

class FeedbackStoreTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        SetupTestDatabase(TEST_DB_PATH);
        auto &fs = FeedbackStore::GetInstance();
        fs.SetDatabasePathForTesting(TEST_DB_PATH);
    }
    void TearDown() override
    {
        FeedbackStore::GetInstance().Clear();
        FeedbackStore::GetInstance().SetDatabasePathForTesting(PERCEPTION_DB_PATH);
        unlink(TEST_DB_PATH);
    }
};

HWTEST_F(FeedbackStoreTest, InsertFeedback_Success, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("BehaviorAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::ACCEPT));
    EXPECT_EQ(record.feedbackTime, 0);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_FiveTypes_SameEventId_UpdatedToLast, TestSize.Level1)
{
    FeedbackType types[] = {
        FeedbackType::ACCEPT,
        FeedbackType::IGNORE,
        FeedbackType::REJECT,
        FeedbackType::EDIT,
        FeedbackType::NOT_PUSHED,
    };
    for (int32_t i = 0; i < 5; ++i) {
        FeedbackData feedback {
            .perceptionEventId = "BehaviorAwareness_1",
            .feedbackType = types[i],
            .feedbackTime = 1000 + i,
        };
        EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    }
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("BehaviorAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::NOT_PUSHED));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Idempotent_SameType, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    std::vector<FeedbackRecord> records;
    FeedbackStore::GetInstance().QueryAll(records);
    int32_t count = 0;
    for (const auto &r : records) {
        if (r.id == 1) {
            ++count;
        }
    }
    EXPECT_EQ(count, 1);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Update_DifferentType, TestSize.Level1)
{
    FeedbackData fb1 {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb1), RET_OK);
    FeedbackData fb2 {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb2), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("BehaviorAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::REJECT));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Mapping_DifferentEventId, TestSize.Level1)
{
    FeedbackData fb1 {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackData fb2 {
        .perceptionEventId = "BehaviorAwareness_2",
        .feedbackType = FeedbackType::IGNORE,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb1), RET_OK);
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb2), RET_OK);
    FeedbackRecord rec1;
    FeedbackRecord rec2;
    FeedbackStore::GetInstance().QueryFeedback("BehaviorAwareness_1", rec1);
    FeedbackStore::GetInstance().QueryFeedback("BehaviorAwareness_2", rec2);
    EXPECT_EQ(rec1.feedbackType, static_cast<int32_t>(FeedbackType::ACCEPT));
    EXPECT_EQ(rec2.feedbackType, static_cast<int32_t>(FeedbackType::IGNORE));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_DbNotExist_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/nonexistent_db.db");
    FeedbackData feedback {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(TEST_DB_PATH);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_RdbStoreNull_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/nonexistent_db.db");
    FeedbackData feedback {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(TEST_DB_PATH);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_RecordNotFound_WarnNoInsert, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "BehaviorAwareness_999",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    FeedbackStore::GetInstance().QueryFeedback("BehaviorAwareness_999", record);
    EXPECT_EQ(record.id, 0);
}

HWTEST_F(FeedbackStoreTest, Clear_RemovesAllRecords, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "BehaviorAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(feedback);
    FeedbackStore::GetInstance().Clear();
    std::vector<FeedbackRecord> records;
    FeedbackStore::GetInstance().QueryAll(records);
    EXPECT_TRUE(records.empty());
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
