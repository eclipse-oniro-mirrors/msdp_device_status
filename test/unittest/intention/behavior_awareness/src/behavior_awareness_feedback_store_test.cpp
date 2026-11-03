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

#include <cstdio>
#include <string>
#include <thread>
#include <vector>

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
constexpr const char *TEST_DB_PATH = "/data/local/tmp/test_habit_perceptions.db";
constexpr int32_t TEST_RECORD_COUNT = 10;
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
    for (int i = 3; i <= TEST_RECORD_COUNT; ++i) {
        std::string sql = "INSERT INTO habit_perceptions (id, e, a, feedback) VALUES (" +
            std::to_string(i) + ", 'time', 'switch', '{}')";
        store->ExecuteSql(sql);
    }
    store->ExecuteSql(
        "INSERT INTO habit_perceptions (id, e, a, feedback) VALUES (2147483647, 'time', 'switch', '{}')");
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
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::ACCEPT));
    EXPECT_EQ(record.feedbackTime, 1000);
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
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = types[i],
            .feedbackTime = 1000 + i,
        };
        EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    }
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::NOT_PUSHED));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Idempotent_SameType, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
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
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb1), RET_OK);
    FeedbackData fb2 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb2), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::REJECT));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Mapping_DifferentEventId, TestSize.Level1)
{
    FeedbackData fb1 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackData fb2 {
        .perceptionEventId = "habitAwareness_2",
        .feedbackType = FeedbackType::IGNORE,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb1), RET_OK);
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb2), RET_OK);
    FeedbackRecord rec1;
    FeedbackRecord rec2;
    FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", rec1);
    FeedbackStore::GetInstance().QueryFeedback("habitAwareness_2", rec2);
    EXPECT_EQ(rec1.feedbackType, static_cast<int32_t>(FeedbackType::ACCEPT));
    EXPECT_EQ(rec2.feedbackType, static_cast<int32_t>(FeedbackType::IGNORE));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_DbNotExist_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/nonexistent_db.db");
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(TEST_DB_PATH);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_InvalidDbFile_ReturnsServiceException, TestSize.Level1)
{
    const char *invalidDbPath = "/data/local/tmp/invalid_habit_perceptions.db";
    FILE *f = fopen(invalidDbPath, "w");
    ASSERT_NE(f, nullptr);
    fputs("not a database", f);
    fclose(f);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(invalidDbPath);
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), SERVICE_EXCEPTION);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(TEST_DB_PATH);
    unlink(invalidDbPath);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_RecordNotFound_WarnNoInsert, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_999",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    FeedbackStore::GetInstance().QueryFeedback("habitAwareness_999", record);
    EXPECT_EQ(record.id, 0);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_LargeEventId, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_2147483647",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_2147483647", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::ACCEPT));
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Timestamp_Preserved, TestSize.Level1)
{
    int64_t largeTime = 1700000000000;
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::EDIT,
        .feedbackTime = largeTime,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackTime, largeTime);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Concurrent_NoRace, TestSize.Level1)
{
    const int threadCount = 10;
    std::vector<std::thread> threads;
    for (int i = 1; i <= threadCount; ++i) {
        threads.emplace_back([i]() {
            FeedbackData feedback {
                .perceptionEventId = "habitAwareness_" + std::to_string(i),
                .feedbackType = FeedbackType::ACCEPT,
                .feedbackTime = 1000 + i,
            };
            EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    std::vector<FeedbackRecord> records;
    FeedbackStore::GetInstance().QueryAll(records);
    int updated = 0;
    for (const auto &r : records) {
        if (r.feedbackType == static_cast<int32_t>(FeedbackType::ACCEPT) && r.feedbackTime > 0) {
            ++updated;
        }
    }
    EXPECT_EQ(updated, threadCount);
}

HWTEST_F(FeedbackStoreTest, Clear_RemovesAllRecords, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(feedback);
    FeedbackStore::GetInstance().Clear();
    std::vector<FeedbackRecord> records;
    FeedbackStore::GetInstance().QueryAll(records);
    EXPECT_TRUE(records.empty());
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_ZeroId_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_0",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
    FeedbackRecord record;
    FeedbackStore::GetInstance().QueryFeedback("habitAwareness_0", record);
    EXPECT_EQ(record.id, 0);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_NegativeId_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_-1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_NonNumericSuffix_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_abc",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_NoUnderscore_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "invalidformat",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_EmptyEventId_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_EmptySuffix_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_MultipleUnderscores_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1_2",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_AllFiveFeedbackTypes_Success, TestSize.Level1)
{
    FeedbackType types[] = {
        FeedbackType::ACCEPT,
        FeedbackType::IGNORE,
        FeedbackType::REJECT,
        FeedbackType::EDIT,
        FeedbackType::NOT_PUSHED,
    };
    for (int32_t i = 0; i < static_cast<int32_t>(sizeof(types) / sizeof(types[0])); ++i) {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_2",
            .feedbackType = types[i],
            .feedbackTime = 1000 + i,
        };
        EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(feedback), RET_OK);
        FeedbackRecord record;
        FeedbackStore::GetInstance().QueryFeedback("habitAwareness_2", record);
        EXPECT_EQ(record.feedbackType, static_cast<int32_t>(types[i]));
    }
}
/* ==================== Branch Coverage Supplement ==================== */

HWTEST_F(FeedbackStoreTest, ParseFeedbackType_ValidJson, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackType("{\"feedbackType\":2}"), 2);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackType_NoKey_ReturnsMinusOne, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackType("{\"otherKey\":1}"), -1);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackType_EmptyJson_ReturnsMinusOne, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackType("{}"), -1);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackType_NonNumeric_ReturnsMinusOne, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackType("{\"feedbackType\":abc}"), -1);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackType_WithTime_ReturnsType, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackType(
        "{\"feedbackType\":3,\"feedbackTime\":1000}"), 3);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackTime_ValidJson, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackTime("{\"feedbackTime\":1000}"), 1000);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackTime_NoKey_ReturnsZero, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackTime("{\"otherKey\":1}"), 0);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackTime_EmptyJson_ReturnsZero, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackTime("{}"), 0);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackTime_NonNumeric_ReturnsZero, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackTime("{\"feedbackTime\":abc}"), 0);
}

HWTEST_F(FeedbackStoreTest, ParseFeedbackTime_WithType_ReturnsTime, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().ParseFeedbackTime(
        "{\"feedbackType\":2,\"feedbackTime\":2000}"), 2000);
}

HWTEST_F(FeedbackStoreTest, MapEventIdToId_Valid, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().MapEventIdToId("habitAwareness_123"), 123);
}

HWTEST_F(FeedbackStoreTest, MapEventIdToId_NoUnderscore, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().MapEventIdToId("invalidformat"), INVALID_ID);
}

HWTEST_F(FeedbackStoreTest, MapEventIdToId_EmptySuffix, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().MapEventIdToId("habitAwareness_"), INVALID_ID);
}

HWTEST_F(FeedbackStoreTest, MapEventIdToId_NonNumeric, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().MapEventIdToId("habitAwareness_abc"), INVALID_ID);
}

HWTEST_F(FeedbackStoreTest, MapEventIdToId_EmptyString, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().MapEventIdToId(""), INVALID_ID);
}

HWTEST_F(FeedbackStoreTest, SerializeFeedbackJson_Valid, TestSize.Level1)
{
    std::string out;
    EXPECT_EQ(FeedbackStore::GetInstance().SerializeFeedbackJson(2, 1000, out), RET_OK);
    EXPECT_TRUE(out.find("\"feedbackType\":2") != std::string::npos);
    EXPECT_TRUE(out.find("\"feedbackTime\":1000") != std::string::npos);
}

HWTEST_F(FeedbackStoreTest, QueryFeedback_NullRdbStore_ReturnsServiceException, TestSize.Level1)
{
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), SERVICE_EXCEPTION);
}

HWTEST_F(FeedbackStoreTest, QueryFeedback_InvalidId_ReturnsServiceException, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("invalidformat", record), SERVICE_EXCEPTION);
}

HWTEST_F(FeedbackStoreTest, QueryFeedback_NotFound_ReturnsRetOk, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_999", record), RET_OK);
    EXPECT_EQ(record.id, 0);
}

HWTEST_F(FeedbackStoreTest, QueryAll_NullRdbStore_ReturnsServiceException, TestSize.Level1)
{
    std::vector<FeedbackRecord> records;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryAll(records), SERVICE_EXCEPTION);
}

HWTEST_F(FeedbackStoreTest, Clear_NullRdbStore_NoCrash, TestSize.Level1)
{
    FeedbackStore::GetInstance().Clear();
}

HWTEST_F(FeedbackStoreTest, QueryFeedbackType_NullRdbStore_ReturnsServiceException, TestSize.Level1)
{
    bool recordFound = false;
    int32_t outType = -1;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedbackType(1, recordFound, outType), SERVICE_EXCEPTION);
    EXPECT_FALSE(recordFound);
    EXPECT_EQ(outType, -1);
}

HWTEST_F(FeedbackStoreTest, UpdateFeedbackField_NullRdbStore_ReturnsServiceException, TestSize.Level1)
{
    EXPECT_EQ(FeedbackStore::GetInstance().UpdateFeedbackField(1, "{}", 1000), SERVICE_EXCEPTION);
}

HWTEST_F(FeedbackStoreTest, EnsureTable_NullRdbStore_ReturnsServiceException, TestSize.Level1)
{
    std::shared_ptr<NativeRdb::Transaction> nullTrans;
    EXPECT_EQ(FeedbackStore::GetInstance().EnsureTable(nullTrans), SERVICE_EXCEPTION);
}

HWTEST_F(FeedbackStoreTest, EnsureTable_NullTransaction_ReturnsServiceException, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    std::shared_ptr<NativeRdb::Transaction> nullTrans;
    EXPECT_EQ(FeedbackStore::GetInstance().EnsureTable(nullTrans), SERVICE_EXCEPTION);
}

HWTEST_F(FeedbackStoreTest, ProcessFeedback_QueryFails_TolerantReturn, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    auto &fs = FeedbackStore::GetInstance();
    fs.rdbStore_ = nullptr;
    FeedbackData fb2 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(fs.ProcessFeedback(1, fb2), RET_OK);
    fs.SetDatabasePathForTesting(TEST_DB_PATH);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_AlreadyInited_SkipsInit, TestSize.Level1)
{
    FeedbackData fb1 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb1), RET_OK);
    FeedbackData fb2 {
        .perceptionEventId = "habitAwareness_2",
        .feedbackType = FeedbackType::IGNORE,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb2), RET_OK);
}

HWTEST_F(FeedbackStoreTest, QueryFeedback_FullField_Parsed, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::EDIT,
        .feedbackTime = 5000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.id, 1);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::EDIT));
    EXPECT_EQ(record.feedbackTime, 5000);
    EXPECT_FALSE(record.feedbackJson.empty());
}

HWTEST_F(FeedbackStoreTest, QueryAll_MultipleRecords, TestSize.Level1)
{
    for (int i = 1; i <= 3; ++i) {
        FeedbackData fb {
            .perceptionEventId = "habitAwareness_" + std::to_string(i),
            .feedbackType = static_cast<FeedbackType>(i % 5),
            .feedbackTime = 1000 + i,
        };
        FeedbackStore::GetInstance().InsertFeedback(fb);
    }
    std::vector<FeedbackRecord> records;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryAll(records), RET_OK);
    EXPECT_GE(records.size(), 3u);
}

HWTEST_F(FeedbackStoreTest, Clear_AfterInsert_RemovesAll, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    FeedbackStore::GetInstance().Clear();
    std::vector<FeedbackRecord> records;
    FeedbackStore::GetInstance().QueryAll(records);
    EXPECT_TRUE(records.empty());
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_Idempotent_SameType_NoUpdate, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb), RET_OK);
}

HWTEST_F(FeedbackStoreTest, QueryFeedback_MalformedJson_DefaultValues, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    auto &fs = FeedbackStore::GetInstance();
    fs.rdbStore_->ExecuteSql("UPDATE habit_perceptions SET feedback='garbage' WHERE id=1");
    FeedbackRecord record;
    EXPECT_EQ(fs.QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, -1);
    EXPECT_EQ(record.feedbackTime, 0);
}

HWTEST_F(FeedbackStoreTest, QueryFeedback_EmptyJson_DefaultValues, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    auto &fs = FeedbackStore::GetInstance();
    fs.rdbStore_->ExecuteSql("UPDATE habit_perceptions SET feedback='{}' WHERE id=1");
    FeedbackRecord record;
    EXPECT_EQ(fs.QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, -1);
    EXPECT_EQ(record.feedbackTime, 0);
}

HWTEST_F(FeedbackStoreTest, QueryAll_MixedJsonFormats, TestSize.Level1)
{
    auto &fs = FeedbackStore::GetInstance();
    FeedbackData fb1 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    fs.InsertFeedback(fb1);
    FeedbackData fb2 {
        .perceptionEventId = "habitAwareness_2",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    fs.InsertFeedback(fb2);
    fs.rdbStore_->ExecuteSql("UPDATE habit_perceptions SET feedback='malformed' WHERE id=2");
    std::vector<FeedbackRecord> records;
    EXPECT_EQ(fs.QueryAll(records), RET_OK);
    EXPECT_GE(records.size(), 2u);
    bool foundValid = false;
    bool foundMalformed = false;
    for (const auto &r : records) {
        if (r.id == 1 && r.feedbackType == static_cast<int32_t>(FeedbackType::ACCEPT)) {
            foundValid = true;
        }
        if (r.id == 2 && r.feedbackType == -1) {
            foundMalformed = true;
        }
    }
    EXPECT_TRUE(foundValid);
    EXPECT_TRUE(foundMalformed);
}

HWTEST_F(FeedbackStoreTest, InsertFeedback_DirectoryPath_ReturnsServiceException, TestSize.Level1)
{
    FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/");
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().InsertFeedback(fb), SERVICE_EXCEPTION);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(TEST_DB_PATH);
}

HWTEST_F(FeedbackStoreTest, QueryFeedbackType_RecordFound_WithValidJson, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    bool recordFound = false;
    int32_t outType = -1;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedbackType(1, recordFound, outType), RET_OK);
    EXPECT_TRUE(recordFound);
    EXPECT_EQ(outType, static_cast<int32_t>(FeedbackType::REJECT));
}

HWTEST_F(FeedbackStoreTest, QueryFeedbackType_RecordNotFound, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    bool recordFound = false;
    int32_t outType = -1;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedbackType(999, recordFound, outType), RET_OK);
    EXPECT_FALSE(recordFound);
}

HWTEST_F(FeedbackStoreTest, UpdateFeedbackField_ValidUpdate, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    EXPECT_EQ(FeedbackStore::GetInstance().UpdateFeedbackField(
        1, "{\"feedbackType\":3,\"feedbackTime\":3000}", 3000), RET_OK);
    FeedbackRecord record;
    FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record);
    EXPECT_EQ(record.feedbackType, 3);
}

HWTEST_F(FeedbackStoreTest, ProcessFeedback_RecordNotFound_TolerantReturn, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_999",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().ProcessFeedback(999, fb), RET_OK);
}

HWTEST_F(FeedbackStoreTest, ProcessFeedback_Idempotent_SameType, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb);
    EXPECT_EQ(FeedbackStore::GetInstance().ProcessFeedback(1, fb), RET_OK);
}

HWTEST_F(FeedbackStoreTest, ProcessFeedback_UpdateDifferentType, TestSize.Level1)
{
    FeedbackData fb1 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    FeedbackStore::GetInstance().InsertFeedback(fb1);
    FeedbackData fb2 {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(FeedbackStore::GetInstance().ProcessFeedback(1, fb2), RET_OK);
    FeedbackRecord record;
    FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::REJECT));
}

} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
