/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "timer_manager_test.h"

#include <unistd.h>
#include "ddm_adapter.h"

#undef LOG_TAG
#define LOG_TAG "TimerManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 100 };
constexpr int32_t DEFAULT_DELAY_TIME { 40 };
constexpr int32_t RETRY_TIME { 2 };
constexpr int32_t DEFAULT_TIMEOUT { 30 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t DEFAULT_UNLOAD_COOLING_TIME_MS { 600 };
constexpr int32_t ERROR_TIMERID { -1 };
constexpr size_t ERROR_REPEAT_COUNT { 128 };
constexpr int32_t ERROR_INTERVAL_MS { 1000000 };
} // namespace

void TimerManagerTest::SetUpTestCase() {}

void TimerManagerTest::TearDownTestCase() {}

void TimerManagerTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
}

void TimerManagerTest::TearDown()
{
    context_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_DELAY_TIME));
}

/**
 * @tc.name: TimerManagerTest_AddTimer001
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_DELAY_TIME, RETRY_TIME, [this, env]() {
        if (timerInfo_.times == 0) {
            FI_HILOGI("It will be retry to call callback next time");
            timerInfo_.times++;
            return;
        }
        env->GetTimerManager().RemoveTimer(timerInfo_.timerId);
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    timerInfo_.timerId = timerId_;
    timerInfo_.times = 0;

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS * RETRY_TIME));
    timerId_ = -1;
    timerInfo_.timerId = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer002
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute one times", timerId_);
        EXPECT_GE(timerId_, 0);
        env->GetTimerManager().RemoveTimer(timerId_);
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer003
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer004
 * @tc.desc: Test AddTimer, Invalid number of repetitions, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, ERROR_REPEAT_COUNT, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimer(timerId_);
        EXPECT_GE(timerId_, 0);
        timerId_ = -1;
    });
    if (timerId_ < 0) {
        FI_HILOGI("Invalid repeat-count value, then error, so success");
    } else {
        FI_HILOGE("Invalid repeat-count value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TimerManagerTest_AddTimer005
 * @tc.desc: Test AddTimer, Invalid interval time, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(ERROR_INTERVAL_MS, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimer(timerId_);
        EXPECT_GE(timerId_, 0);
    });
    if (timerId_ < 0) {
        FI_HILOGI("Invalid interval value, then error, so success");
    } else {
        FI_HILOGE("Invalid interval value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimer006
 * @tc.desc: Test AddTimer, Invalid callback function, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimer006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimer(ERROR_INTERVAL_MS, REPEAT_ONCE, nullptr);
    if (timerId_ < 0) {
        FI_HILOGI("Invalid callback value, then error, so success");
    } else {
        FI_HILOGE("Invalid callback value, but okay, so failed");
    }

    EXPECT_LT(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync001
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_DELAY_TIME, RETRY_TIME, [this, env]() {
        if (timerInfo_.times == 0) {
            FI_HILOGI("It will be retry to call callback next time");
            timerInfo_.times++;
        } else {
            env->GetTimerManager().RemoveTimerAsync(timerInfo_.timerId);
        }
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    timerInfo_.timerId = timerId_;
    timerInfo_.times = 0;

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS * RETRY_TIME));
    timerId_ = -1;
    timerInfo_.timerId = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync002
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute one times", timerId_);
        EXPECT_GE(timerId_, 0);
        env->GetTimerManager().RemoveTimerAsync(timerId_);
    });
    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync003
 * @tc.desc: Test AddTimer, Parameter correct expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimerAsync(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync004
 * @tc.desc: Test AddTimer, Invalid number of repetitions, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(DEFAULT_TIMEOUT, ERROR_REPEAT_COUNT, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimerAsync(timerId_);
        EXPECT_GE(timerId_, 0);
        timerId_ = -1;
    });

    if (timerId_ < 0) {
        FI_HILOGI("Invalid repeat-count value, then error, so success");
    } else {
        FI_HILOGE("Invalid repeat-count value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync005
 * @tc.desc: Test AddTimer, Invalid interval time, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimerAsync(ERROR_INTERVAL_MS, REPEAT_ONCE, [this, env]() {
        FI_HILOGI("Timer %{public}d excute onetimes", timerId_);
        env->GetTimerManager().RemoveTimerAsync(timerId_);
        EXPECT_GE(timerId_, 0);
    });
    if (timerId_ < 0) {
        FI_HILOGI("Invalid interval value, then error, so success");
    } else {
        FI_HILOGE("Invalid interval value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_AddTimerAsync006
 * @tc.desc: Test AddTimer, Invalid callback function, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_AddTimerAsync006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);
    timerId_ = env->GetTimerManager().AddTimerAsync(ERROR_INTERVAL_MS, REPEAT_ONCE, nullptr);
    if (timerId_ < 0) {
        FI_HILOGI("Invalid callback value, then error, so success");
    } else {
        FI_HILOGE("Invalid callback value, but okay, so failed");
    }

    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_GetTimerFd001
 * @tc.desc: Test GetTimerFd, Obtaining initialized TimerFd, expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_GetTimerFd001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);
    TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
    int32_t timerFd = timerMgr->GetTimerFd();
    if (timerFd < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }
    EXPECT_GE(timerFd, 0);
}

/**
 * @tc.name: TimerManagerTest_GetTimerFd002
 * @tc.desc: Test GetTimerFd, Uninitialized, directly obtaining TimerFd, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_GetTimerFd002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timerMgr;
    int32_t timerFd = timerMgr.GetTimerFd();
    if (timerFd < 0) {
        FI_HILOGI("TimerFd is less than zero. the value is %{public}d", timerFd);
    } else {
        FI_HILOGE("Get TimerFd failed. the value is %{public}d", timerFd);
    }
    EXPECT_LT(timerFd, 0);
}

/**
 * @tc.name: TimerManagerTest_IsExist001
 * @tc.desc: Test IsExist, The newly added clock ID has been determined to exist and is expected to succeed
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_IsExist001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("Add the timer %{public}d success", timerId_);
    }
    EXPECT_GE(timerId_, 0);
    TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
    bool exist = timerMgr->IsExist(timerId_);
    if (exist) {
        FI_HILOGI("timerId_ is exist, so success");
    } else {
        FI_HILOGE("timerId_ is exist, but response unexist, so failed");
    }
    EXPECT_TRUE(exist);

    exist = timerMgr->IsExist(ERROR_TIMERID);
    if (!exist) {
        FI_HILOGI("The TimerFd(-1) does not exist, so success");
    } else {
        FI_HILOGE("The TimerFd(-1) does not exist, but response exist, so failed");
    }
    EXPECT_FALSE(exist);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_IsExist002
 * @tc.desc: Test IsExist, Invalid clock ID, determine if it does not exist
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_IsExist002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TimerManager timerMgr;
    bool exist = timerMgr.IsExist(ERROR_TIMERID);

    if (!exist) {
        FI_HILOGI("The TimerFd(-1) is not exist, so success");
    } else {
        FI_HILOGE("The TimerFd(-1) is not exist, but response exist, so failed");
    }
    EXPECT_FALSE(exist);
}

/**
 * @tc.name: TimerManagerTest_ResetTimer001
 * @tc.desc: Test ResetTimer, After adding the clock and resetting it, expected success
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_UNLOAD_COOLING_TIME_MS, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
        int32_t ret = timerMgr->ResetTimer(timerId_);
        if (ret == RET_OK) {
            FI_HILOGI("Reset timer success");
        } else {
            FI_HILOGI("Reset timer %{public}d failed", timerId_);
        }
        EXPECT_EQ(ret, RET_OK);
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_UNLOAD_COOLING_TIME_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_ResetTimer002
 * @tc.desc: Test ResetTimer, Reset after deleting clock, expected failure
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_ResetTimer002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            env->GetTimerManager().RemoveTimer(timerId_);
            EXPECT_GE(timerId_, 0);
            TimerManager *timerMgr = static_cast<TimerManager *>(&env->GetTimerManager());
            int32_t ret = timerMgr->ResetTimer(timerId_);
            if (ret == RET_ERR) {
                FI_HILOGI("Reset unexist timerid sucess");
            } else {
                FI_HILOGE("Reset unexist timerid %{public}d failed", timerId_);
            }
            EXPECT_EQ(ret, RET_ERR);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("AddTimer success");
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}

/**
 * @tc.name: TimerManagerTest_RemoveTimer001
 * @tc.desc: Test RemoveTimer, Repeated deletion of clock, first successful, others failed
 * @tc.type: FUNC
 */
HWTEST_F(TimerManagerTest, TimerManagerTest_RemoveTimer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = context_;
    ASSERT_NE(env, nullptr);

    timerId_ = env->GetTimerManager().AddTimer(DEFAULT_TIMEOUT, REPEAT_ONCE, [this, env]() {
        if (timerId_ >= 0) {
            int32_t ret = env->GetTimerManager().RemoveTimer(timerId_);
            ret = env->GetTimerManager().RemoveTimer(timerId_);
            if (ret == RET_ERR) {
                FI_HILOGI("Remove timer two times, then error, this case success");
            } else {
                FI_HILOGE("Remove timer two times, but okay, this case failed");
            }
            EXPECT_EQ(ret, RET_ERR);
        }
    });

    if (timerId_ < 0) {
        FI_HILOGE("AddTimer failed");
    } else {
        FI_HILOGI("AddTimer success");
    }
    EXPECT_GE(timerId_, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    timerId_ = -1;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS