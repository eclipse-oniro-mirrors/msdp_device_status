/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "ani_drop_event.h"
#include "ani_error_utils.h"
#include "motion_client.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
namespace {
using namespace testing::ext;
constexpr int32_t DROP_TYPE = 1600;
constexpr int32_t OTHER_TYPE = 1601;

constexpr int32_t MOTION_OPERATION_FAILED = -2;
constexpr int32_t MOTION_SERVICE_FAILED = -1;
constexpr int32_t MOTION_SUBSCRIBE_EXCEPTION = 31500002;
constexpr int32_t MOTION_UNSUBSCRIBE_EXCEPTION = 31500003;
constexpr int32_t NON_SYSTEM_APP_ERROR = 202;

constexpr int32_t MOTION_STATUS_INVALID = -1;
constexpr int32_t MOTION_STATUS_FREE_FALL_15_CM = 1;
constexpr int32_t MOTION_STATUS_FREE_FALL_50_CM = 2;
constexpr int32_t MOTION_STATUS_FREE_FALL_30_CM = 3;
constexpr int32_t MOTION_STATUS_KNOCK = 4;
constexpr int32_t UNDEFINED_MOTION_STATUS = 5;
constexpr int32_t OUT_OF_RANGE_MOTION_STATUS = 42;

constexpr std::size_t EXPECTED_CALLBACK_COUNT = 2;
constexpr int32_t EXPECTED_MOTION_CALL_COUNT = 2;
constexpr int32_t EXPECTED_ERROR_CHECK_COUNT = 2;

// These ANI function tables support native C++ Taihe callbacks only. They do not
// emulate an ArkTS VM, public API declarations, BusinessError construction or IPC.
std::atomic<bool> g_envAvailable {true};
std::atomic<bool> g_pendingError {false};
std::atomic<int32_t> g_errorChecks {0};

ani_status TestExistUnhandledError(ani_env *, ani_boolean *result)
{
    ++g_errorChecks;
    *result = g_pendingError.load() ? ANI_TRUE : ANI_FALSE;
    return ANI_OK;
}

const __ani_interaction_api ENV_API = []() {
    __ani_interaction_api api {};
    api.ExistUnhandledError = TestExistUnhandledError;
    return api;
}();
ani_env g_testEnv {&ENV_API};

ani_status TestGetEnv(ani_vm *, uint32_t, ani_env **result)
{
    *result = g_envAvailable.load() ? &g_testEnv : nullptr;
    return ANI_OK;
}

const __ani_vm_api VM_API = []() {
    __ani_vm_api api {};
    api.GetEnv = TestGetEnv;
    return api;
}();
ani_vm g_testVm {&VM_API};

class AniDropEventTest : public testing::Test {
public:
    void SetUp() override
    {
        previousVm_ = ::taihe::get_vm();
        ::taihe::set_vm(&g_testVm);
        g_envAvailable = true;
        g_pendingError = false;
        g_errorChecks = 0;
        MotionClient::GetInstance().Reset();
        subject_ = AniMotionEvent::GetInstance();
        runner_ = AppExecFwk::EventRunner::Create("AniDropEventTest");
        ASSERT_NE(runner_, nullptr);
        handler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
        Run([this]() { ClearState(); });
    }

    void TearDown() override
    {
        if (handler_ != nullptr) {
            Run([this]() { ClearState(); });
            Drain();
        }
        MotionClient::GetInstance().Reset();
        handler_.reset();
        runner_.reset();
        subject_.reset();
        ::taihe::set_vm(previousVm_);
    }

protected:
    void Run(const std::function<void()> &action)
    {
        // LOW is a barrier after the production IMMEDIATE event tasks.
        ASSERT_TRUE(handler_->PostSyncTask(action, "AniDropEventTest.barrier",
            AppExecFwk::EventQueue::Priority::LOW));
    }

    void Drain()
    {
        Run([]() {});
    }

    void ClearState()
    {
        for (auto &entry : subject_->events_) {
            for (auto &record : entry.second) {
                record->active.store(false);
            }
        }
        subject_->events_.clear();
        subject_->callbacks_.clear();
    }

    DropDetectCallback MakeCallback(const std::function<void(DropDetectionStatus_t)> &action)
    {
        return ::taihe::into_holder<::taihe::callback<void(DropDetectionStatus_t)>>(action);
    }

    DropDetectCallback RecordingCallback(std::vector<int32_t> &values)
    {
        return MakeCallback([&values](DropDetectionStatus_t status) { values.push_back(status.get_value()); });
    }

    int32_t Subscribe(const DropDetectCallback &callback)
    {
        int32_t result = SERVICE_EXCEPTION;
        Run([&]() { result = subject_->SubscribeCallback(DROP_TYPE, callback); });
        return result;
    }

    int32_t Unsubscribe(const DropDetectCallback *callback)
    {
        int32_t result = SERVICE_EXCEPTION;
        Run([&]() { result = subject_->UnSubscribeCallback(DROP_TYPE, callback); });
        return result;
    }

    void Emit(int32_t status, int32_t type = DROP_TYPE)
    {
        auto event = std::make_shared<MotionEvent>();
        event->type = type;
        event->status = status;
        subject_->OnEventDropDetection(type, event);
    }

    std::shared_ptr<AniMotionEvent> subject_;
    std::shared_ptr<AppExecFwk::EventRunner> runner_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
    ani_vm *previousVm_ {nullptr};
    std::vector<int32_t> received_;
};

HWTEST_F(AniDropEventTest, SingletonIsStable, TestSize.Level1)
{
    EXPECT_EQ(subject_, AniMotionEvent::GetInstance());
}

HWTEST_F(AniDropEventTest, FirstSubscriptionCallsMotionOnce, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    auto &motion = MotionClient::GetInstance();
    EXPECT_EQ(motion.subscribeCalls, 1);
    EXPECT_EQ(motion.lastSubscribeType, DROP_TYPE);
    EXPECT_NE(motion.lastCallback, nullptr);
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, DistinctCallbacksShareNativeSubscription, TestSize.Level1)
{
    std::vector<int32_t> other;
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(other);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    EXPECT_EQ(MotionClient::GetInstance().subscribeCalls, 1);
    Run([&]() { EXPECT_EQ(subject_->events_.at(DROP_TYPE).size(), EXPECTED_CALLBACK_COUNT); });
}

HWTEST_F(AniDropEventTest, DuplicateReturnsSubscribeErrorAndKeepsOriginal, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    EXPECT_EQ(Subscribe(callback), SUBSCRIBE_EXCEPTION);
    EXPECT_EQ(MotionClient::GetInstance().subscribeCalls, 1);
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_15_CM); });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
    EXPECT_EQ(Unsubscribe(&callback), 0);
}

HWTEST_F(AniDropEventTest, SubscribeFailureMapsErrorsAndRollsBack, TestSize.Level1)
{
    const std::vector<std::pair<int32_t, int32_t>> errors {
        {MOTION_OPERATION_FAILED, SUBSCRIBE_EXCEPTION},
        {MOTION_SUBSCRIBE_EXCEPTION, SUBSCRIBE_EXCEPTION},
        {SUBSCRIBE_EXCEPTION, SUBSCRIBE_EXCEPTION},
        {DEVICE_EXCEPTION, DEVICE_EXCEPTION},
        {MOTION_SERVICE_FAILED, SERVICE_EXCEPTION},
        {NON_SYSTEM_APP_ERROR, SERVICE_EXCEPTION},
        {MOTION_UNSUBSCRIBE_EXCEPTION, SERVICE_EXCEPTION},
        {UNSUBSCRIBE_EXCEPTION, SERVICE_EXCEPTION},
    };
    auto callback = RecordingCallback(received_);
    for (const auto &error : errors) {
        SCOPED_TRACE(error.first);
        MotionClient::GetInstance().subscribeResult = error.first;
        EXPECT_EQ(Subscribe(callback), error.second);
        Run([&]() {
            EXPECT_TRUE(subject_->events_.empty());
            EXPECT_TRUE(subject_->callbacks_.empty());
        });
    }
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 0);
}

HWTEST_F(AniDropEventTest, FailedSubscriptionCanBeRetried, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    auto &motion = MotionClient::GetInstance();
    motion.subscribeResult = MOTION_OPERATION_FAILED;
    EXPECT_EQ(Subscribe(callback), SUBSCRIBE_EXCEPTION);
    motion.subscribeResult = 0;
    ASSERT_EQ(Subscribe(callback), 0);
    EXPECT_EQ(motion.subscribeCalls, EXPECTED_MOTION_CALL_COUNT);
    EXPECT_EQ(Unsubscribe(&callback), 0);
}

HWTEST_F(AniDropEventTest, UnknownCallbackOnEmptyReturnsUnsubscribeError, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    EXPECT_EQ(Unsubscribe(&callback), UNSUBSCRIBE_EXCEPTION);
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 0);
}

HWTEST_F(AniDropEventTest, UnknownCallbackKeepsExistingSubscription, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    auto unknown = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    EXPECT_EQ(Unsubscribe(&unknown), UNSUBSCRIBE_EXCEPTION);
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 0);
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_50_CM); });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, RemoveOneKeepsOtherAndNativeSubscription, TestSize.Level1)
{
    std::vector<int32_t> other;
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(other);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    ASSERT_EQ(Unsubscribe(&first), 0);
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 0);
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_30_CM); });
    Drain();
    EXPECT_TRUE(received_.empty());
    EXPECT_EQ(other, std::vector<int32_t>({1}));
    EXPECT_EQ(Subscribe(second), SUBSCRIBE_EXCEPTION);
}

HWTEST_F(AniDropEventTest, LastRemovalUnsubscribesOriginalNativeCallback, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    auto nativeCallback = MotionClient::GetInstance().lastCallback;
    ASSERT_EQ(Unsubscribe(&callback), 0);
    auto &motion = MotionClient::GetInstance();
    EXPECT_EQ(motion.unsubscribeCalls, 1);
    EXPECT_EQ(motion.lastUnsubscribeType, DROP_TYPE);
    EXPECT_EQ(motion.lastUnsubscribeCallback, nativeCallback);
    Run([&]() {
        EXPECT_TRUE(subject_->events_.empty());
        EXPECT_TRUE(subject_->callbacks_.empty());
    });
}

HWTEST_F(AniDropEventTest, CancelAllRemovesEveryCallback, TestSize.Level1)
{
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    ASSERT_EQ(Unsubscribe(nullptr), 0);
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 1);
    EXPECT_EQ(Unsubscribe(&first), UNSUBSCRIBE_EXCEPTION);
    EXPECT_EQ(Unsubscribe(&second), UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(AniDropEventTest, CancelAllOnEmptyReturnsUnsubscribeError, TestSize.Level1)
{
    EXPECT_EQ(Unsubscribe(nullptr), UNSUBSCRIBE_EXCEPTION);
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 0);
}

HWTEST_F(AniDropEventTest, RepeatedRemovalDoesNotCallMotionAgain, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    ASSERT_EQ(Unsubscribe(&callback), 0);
    EXPECT_EQ(Unsubscribe(&callback), UNSUBSCRIBE_EXCEPTION);
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 1);
}

HWTEST_F(AniDropEventTest, ResubscriptionCreatesFreshNativeSubscriptionWithoutReplay, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_15_CM); });
    Drain();
    ASSERT_EQ(Unsubscribe(&callback), 0);
    received_.clear();
    ASSERT_EQ(Subscribe(callback), 0);
    Drain();
    EXPECT_TRUE(received_.empty());
    EXPECT_EQ(MotionClient::GetInstance().subscribeCalls, EXPECTED_MOTION_CALL_COUNT);
}

HWTEST_F(AniDropEventTest, NewCallbackDoesNotReceivePreviousEvent, TestSize.Level1)
{
    std::vector<int32_t> other;
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(other);
    ASSERT_EQ(Subscribe(first), 0);
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_15_CM); });
    Drain();
    ASSERT_EQ(Subscribe(second), 0);
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
    EXPECT_TRUE(other.empty());
}

HWTEST_F(AniDropEventTest, UnsubscribeFailureMapsErrorsAndInvalidatesLocalRecord, TestSize.Level1)
{
    const std::vector<std::pair<int32_t, int32_t>> errors {
        {MOTION_OPERATION_FAILED, UNSUBSCRIBE_EXCEPTION},
        {MOTION_UNSUBSCRIBE_EXCEPTION, UNSUBSCRIBE_EXCEPTION},
        {UNSUBSCRIBE_EXCEPTION, UNSUBSCRIBE_EXCEPTION},
        {DEVICE_EXCEPTION, DEVICE_EXCEPTION},
        {MOTION_SERVICE_FAILED, SERVICE_EXCEPTION},
        {NON_SYSTEM_APP_ERROR, SERVICE_EXCEPTION},
        {MOTION_SUBSCRIBE_EXCEPTION, SERVICE_EXCEPTION},
        {SUBSCRIBE_EXCEPTION, SERVICE_EXCEPTION},
    };
    auto callback = RecordingCallback(received_);
    for (const auto &error : errors) {
        SCOPED_TRACE(error.first);
        auto &motion = MotionClient::GetInstance();
        motion.Reset();
        ASSERT_EQ(Subscribe(callback), 0);
        motion.unsubscribeResult = error.first;
        EXPECT_EQ(Unsubscribe(&callback), error.second);
        Run([&]() {
            EXPECT_TRUE(subject_->events_.empty());
            EXPECT_EQ(subject_->callbacks_.size(), 1u);
            Emit(MOTION_STATUS_FREE_FALL_15_CM);
        });
        Drain();
        EXPECT_TRUE(received_.empty());
        EXPECT_EQ(Unsubscribe(&callback), UNSUBSCRIBE_EXCEPTION);
        Run([&]() { ClearState(); });
    }
}

HWTEST_F(AniDropEventTest, NativeSubscriptionIsReusedAfterFailedUnsubscribe, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    auto &motion = MotionClient::GetInstance();
    ASSERT_EQ(Subscribe(callback), 0);
    motion.unsubscribeResult = MOTION_OPERATION_FAILED;
    EXPECT_EQ(Unsubscribe(&callback), UNSUBSCRIBE_EXCEPTION);
    ASSERT_EQ(Subscribe(callback), 0);
    EXPECT_EQ(motion.subscribeCalls, 1);
    motion.unsubscribeResult = 0;
    EXPECT_EQ(Unsubscribe(&callback), 0);
    EXPECT_EQ(motion.unsubscribeCalls, EXPECTED_MOTION_CALL_COUNT);
}

HWTEST_F(AniDropEventTest, EachRawDropStateMapsToDropped, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        for (int32_t status : {MOTION_STATUS_FREE_FALL_15_CM, MOTION_STATUS_FREE_FALL_50_CM,
            MOTION_STATUS_FREE_FALL_30_CM, MOTION_STATUS_KNOCK}) {
            Emit(status);
        }
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1, 1, 1, 1}));
}

HWTEST_F(AniDropEventTest, NormalAndInvalidSentinelFollowCurrentMapping, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        Emit(0);
        Emit(MOTION_STATUS_INVALID);
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({0, 0}));
}

HWTEST_F(AniDropEventTest, OtherRawValuesFollowCurrentNonzeroMapping, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        Emit(UNDEFINED_MOTION_STATUS);
        Emit(OUT_OF_RANGE_MOTION_STATUS);
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1, 1}));
}

HWTEST_F(AniDropEventTest, ConsecutiveIdenticalEventsAreNotDeduplicated, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1, 1}));
}

HWTEST_F(AniDropEventTest, EventIsDeliveredToBothCallbacks, TestSize.Level1)
{
    std::vector<int32_t> other;
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(other);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    Run([&]() { Emit(MOTION_STATUS_KNOCK); });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
    EXPECT_EQ(other, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, NullAndUnregisteredEventsAreIgnored, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        subject_->OnEventDropDetection(DROP_TYPE, nullptr);
        Emit(MOTION_STATUS_FREE_FALL_15_CM, OTHER_TYPE);
    });
    Drain();
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, NativeCallbackForwardsTypeAndStatus, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    auto nativeCallback = MotionClient::GetInstance().lastCallback;
    Run([&]() {
        MotionEvent ignored {OTHER_TYPE, MOTION_STATUS_FREE_FALL_15_CM};
        MotionEvent dropped {DROP_TYPE, MOTION_STATUS_KNOCK};
        nativeCallback->OnMotionChanged(ignored);
        nativeCallback->OnMotionChanged(dropped);
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, NativeCallbackRejectsNullData, TestSize.Level1)
{
    AniMotionCallback callback;
    callback.EmitOnEvent(nullptr);
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, DeliveryIsAlwaysQueued, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        EXPECT_TRUE(received_.empty());
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, SynchronousSubscribeEventIsDispatchedAfterIpcReturns, TestSize.Level1)
{
    bool insideNativeCall = false;
    auto callback = MakeCallback([this, &insideNativeCall](DropDetectionStatus_t status) {
        EXPECT_FALSE(insideNativeCall);
        received_.push_back(status.get_value());
    });
    MotionClient::GetInstance().subscribeHook = [&](const sptr<IMotionCallback> &nativeCallback) {
        insideNativeCall = true;
        MotionEvent event {DROP_TYPE, MOTION_STATUS_FREE_FALL_15_CM};
        nativeCallback->OnMotionChanged(event);
        EXPECT_TRUE(received_.empty());
        insideNativeCall = false;
    };
    ASSERT_EQ(Subscribe(callback), 0);
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, FailedSubscribeDiscardsEventQueuedDuringIpc, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    auto &motion = MotionClient::GetInstance();
    motion.subscribeResult = MOTION_OPERATION_FAILED;
    motion.subscribeHook = [](const sptr<IMotionCallback> &nativeCallback) {
        MotionEvent event {DROP_TYPE, MOTION_STATUS_FREE_FALL_15_CM};
        nativeCallback->OnMotionChanged(event);
    };
    EXPECT_EQ(Subscribe(callback), SUBSCRIBE_EXCEPTION);
    Drain();
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, RemovedRecordIsNotRetainedByQueuedEvent, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    std::weak_ptr<DropCallbackInfo> weakRecord;
    Run([&]() {
        weakRecord = subject_->events_.at(DROP_TYPE).front();
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        ASSERT_EQ(subject_->UnSubscribeCallback(DROP_TYPE, &callback), 0);
        EXPECT_TRUE(weakRecord.expired());
    });
    Drain();
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, InactiveRecordIsIgnoredEvenWhenStillAlive, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    std::shared_ptr<DropCallbackInfo> oldRecord;
    Run([&]() {
        oldRecord = subject_->events_.at(DROP_TYPE).front();
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        ASSERT_EQ(subject_->UnSubscribeCallback(DROP_TYPE, &callback), 0);
        EXPECT_FALSE(oldRecord->active.load());
    });
    Drain();
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, ResubscribedCallbackCannotReceiveOldQueuedEvent, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        ASSERT_EQ(subject_->UnSubscribeCallback(DROP_TYPE, &callback), 0);
        ASSERT_EQ(subject_->SubscribeCallback(DROP_TYPE, callback), 0);
    });
    Drain();
    EXPECT_TRUE(received_.empty());
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_50_CM); });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, CancelAllDiscardsQueuedEvents, TestSize.Level1)
{
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    Run([&]() {
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        ASSERT_EQ(subject_->UnSubscribeCallback(DROP_TYPE, nullptr), 0);
    });
    Drain();
    EXPECT_TRUE(received_.empty());
}

HWTEST_F(AniDropEventTest, CancelOneDiscardsOnlyItsQueuedDelivery, TestSize.Level1)
{
    std::vector<int32_t> other;
    auto first = RecordingCallback(received_);
    auto second = RecordingCallback(other);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    Run([&]() {
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        ASSERT_EQ(subject_->UnSubscribeCallback(DROP_TYPE, &first), 0);
    });
    Drain();
    EXPECT_TRUE(received_.empty());
    EXPECT_EQ(other, std::vector<int32_t>({1}));
}

HWTEST_F(AniDropEventTest, CallbackCanCancelAllWithoutDeadlock, TestSize.Level1)
{
    auto callback = MakeCallback([this](DropDetectionStatus_t status) {
        received_.push_back(status.get_value());
        EXPECT_EQ(subject_->UnSubscribeCallback(DROP_TYPE, nullptr), 0);
    });
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
    });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
    EXPECT_EQ(MotionClient::GetInstance().unsubscribeCalls, 1);
}

HWTEST_F(AniDropEventTest, MissingAniEnvironmentDropsDelivery, TestSize.Level1)
{
    auto callback = RecordingCallback(received_);
    ASSERT_EQ(Subscribe(callback), 0);
    Run([&]() {
        g_envAvailable = false;
        Emit(MOTION_STATUS_FREE_FALL_15_CM);
    });
    Drain();
    EXPECT_TRUE(received_.empty());
    EXPECT_EQ(g_errorChecks.load(), 0);
    g_envAvailable = true;
}

HWTEST_F(AniDropEventTest, PendingCallbackErrorDoesNotPreventOtherDelivery, TestSize.Level1)
{
    std::vector<int32_t> other;
    auto first = MakeCallback([this](DropDetectionStatus_t status) {
        received_.push_back(status.get_value());
        g_pendingError = true;
    });
    auto second = RecordingCallback(other);
    ASSERT_EQ(Subscribe(first), 0);
    ASSERT_EQ(Subscribe(second), 0);
    Run([&]() { Emit(MOTION_STATUS_FREE_FALL_15_CM); });
    Drain();
    EXPECT_EQ(received_, std::vector<int32_t>({1}));
    EXPECT_EQ(other, std::vector<int32_t>({1}));
    EXPECT_EQ(g_errorChecks.load(), EXPECTED_ERROR_CHECK_COUNT);
}
} // namespace
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
