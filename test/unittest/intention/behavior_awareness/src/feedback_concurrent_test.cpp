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

#include <gtest/gtest.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "accesstoken_kit.h"
#include "behavior_awareness_data.h"
#include "behavior_awareness_server.h"
#include "devicestatus_define.h"
#include "feedback_store.h"
#include "fi_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "parameters.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "FeedbackConcurrentTest"

using namespace testing::ext;

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
using namespace Security::AccessToken;
namespace {
constexpr const char *CONCURRENT_DB_PATH = "/data/local/tmp/test_concurrent_habit_perceptions.db";
constexpr int32_t CONCURRENT_THREAD_COUNT = 10;
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

class ConcurrentTestCallback : public NativeRdb::RdbOpenCallback {
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

void SetupConcurrentDatabase(const std::string &path)
{
    unlink(path.c_str());
    NativeRdb::RdbStoreConfig config(path);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    ConcurrentTestCallback callback;
    auto store = NativeRdb::RdbHelper::GetRdbStore(config, 1, callback, errCode);
    if (store == nullptr) {
        return;
    }
    store->ExecuteSql(
        "INSERT INTO habit_perceptions (id, e, a, feedback) VALUES (1, 'time', 'switch', '{}')");
}

uint64_t NativeTokenGet()
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };
    infoInstance.processName = "FeedbackConcurrentTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

CallingContext MakeSystemContext()
{
    NativeTokenGet();
    return CallingContext {
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
}

CallingContext MakeNonSystemContext()
{
    return CallingContext {
        .fullTokenId = 0,
        .tokenId = 0,
        .uid = 10000,
        .pid = 10000,
    };
}
} // namespace

class FeedbackConcurrentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
        if (deviceType != "phone") {
            GTEST_SKIP() << "BehaviorAwareness only supports phone, current device: " << deviceType;
        }
        SetupConcurrentDatabase(CONCURRENT_DB_PATH);
        auto &fs = FeedbackStore::GetInstance();
        fs.SetDatabasePathForTesting(CONCURRENT_DB_PATH);
        NativeTokenGet();
    }
    void TearDown() override
    {
        FeedbackStore::GetInstance().Clear();
        FeedbackStore::GetInstance().SetDatabasePathForTesting(PERCEPTION_DB_PATH);
        unlink(CONCURRENT_DB_PATH);
    }
};

HWTEST_F(FeedbackConcurrentTest, InsertFeedback_Concurrent_SameEventId, TestSize.Level1)
{
    FeedbackType types[] = {
        FeedbackType::ACCEPT,
        FeedbackType::IGNORE,
        FeedbackType::REJECT,
        FeedbackType::EDIT,
        FeedbackType::NOT_PUSHED,
    };
    std::vector<std::thread> threads;
    std::atomic<int32_t> successCount { 0 };
    for (int32_t i = 0; i < CONCURRENT_THREAD_COUNT; ++i) {
        threads.emplace_back([i, &types, &successCount]() {
            FeedbackData feedback {
                .perceptionEventId = "habitAwareness_1",
                .feedbackType = types[i % static_cast<int32_t>(sizeof(types) / sizeof(types[0]))],
                .feedbackTime = 1000 + i,
            };
            int32_t ret = FeedbackStore::GetInstance().InsertFeedback(feedback);
            if (ret == RET_OK) {
                ++successCount;
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    EXPECT_EQ(successCount.load(), CONCURRENT_THREAD_COUNT);
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

HWTEST_F(FeedbackConcurrentTest, SubmitFeedback_Concurrent_ClientIsolation, TestSize.Level1)
{
    std::atomic<int32_t> paramExceptionCount { 0 };
    std::atomic<int32_t> successCount { 0 };
    auto ctx = MakeSystemContext();
    std::thread clientA([&ctx, &paramExceptionCount]() {
        FeedbackData invalidFeedback {
            .perceptionEventId = "",
            .feedbackType = FeedbackType::ACCEPT,
            .feedbackTime = 1000,
        };
        BehaviorAwarenessServer server;
        int32_t ret = server.SubmitFeedback(ctx, invalidFeedback);
        if (ret == PARAM_EXCEPTION) {
            ++paramExceptionCount;
        }
    });
    std::thread clientB([&ctx, &successCount]() {
        FeedbackData validFeedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = FeedbackType::ACCEPT,
            .feedbackTime = 1000,
        };
        BehaviorAwarenessServer server;
        int32_t ret = server.SubmitFeedback(ctx, validFeedback);
        if (ret == RET_OK) {
            ++successCount;
        }
    });
    clientA.join();
    clientB.join();
    EXPECT_EQ(paramExceptionCount.load(), 1);
    EXPECT_EQ(successCount.load(), 1);
}

HWTEST_F(FeedbackConcurrentTest, SubmitFeedback_MultiClient_PermissionIsolation, TestSize.Level1)
{
    std::atomic<int32_t> notSystemAppCount { 0 };
    std::atomic<int32_t> successCount { 0 };
    auto sysCtx = MakeSystemContext();
    auto nonSysCtx = MakeNonSystemContext();
    std::thread clientA([&nonSysCtx, &notSystemAppCount]() {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = FeedbackType::ACCEPT,
            .feedbackTime = 1000,
        };
        BehaviorAwarenessServer server;
        int32_t ret = server.SubmitFeedback(nonSysCtx, feedback);
        if (ret == COMMON_NOT_SYSTEM_APP) {
            ++notSystemAppCount;
        }
    });
    std::thread clientB([&sysCtx, &successCount]() {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = FeedbackType::ACCEPT,
            .feedbackTime = 1000,
        };
        BehaviorAwarenessServer server;
        int32_t ret = server.SubmitFeedback(sysCtx, feedback);
        if (ret == RET_OK) {
            ++successCount;
        }
    });
    clientA.join();
    clientB.join();
    EXPECT_EQ(notSystemAppCount.load(), 1);
    EXPECT_EQ(successCount.load(), 1);
}

HWTEST_F(FeedbackConcurrentTest, SubmitFeedback_MultiClient_ServiceNotStarted, TestSize.Level1)
{
    const char *invalidDbPath = "/data/local/tmp/invalid_concurrent_habit_perceptions.db";
    FILE *f = fopen(invalidDbPath, "w");
    ASSERT_NE(f, nullptr);
    fputs("not a database", f);
    fclose(f);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(invalidDbPath);
    auto ctx = MakeSystemContext();
    std::atomic<int32_t> serviceExceptionCount { 0 };
    std::thread clientA([&ctx, &serviceExceptionCount]() {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = FeedbackType::ACCEPT,
            .feedbackTime = 1000,
        };
        BehaviorAwarenessServer server;
        int32_t ret = server.SubmitFeedback(ctx, feedback);
        if (ret == SERVICE_EXCEPTION) {
            ++serviceExceptionCount;
        }
    });
    std::thread clientB([&ctx, &serviceExceptionCount]() {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = FeedbackType::IGNORE,
            .feedbackTime = 2000,
        };
        BehaviorAwarenessServer server;
        int32_t ret = server.SubmitFeedback(ctx, feedback);
        if (ret == SERVICE_EXCEPTION) {
            ++serviceExceptionCount;
        }
    });
    clientA.join();
    clientB.join();
    EXPECT_EQ(serviceExceptionCount.load(), 2);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(CONCURRENT_DB_PATH);
    unlink(invalidDbPath);
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
