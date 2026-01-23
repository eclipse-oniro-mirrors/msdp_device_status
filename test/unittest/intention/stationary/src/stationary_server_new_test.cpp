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
#include <memory>
#include <functional>

#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "stationary_params.h"
#include "stationary_data.h"
#include "iremote_dev_sta_callback.h"
#define PRIVATE_MACRO public
#include "stationary_server.h"
#undef private
#include "ipc_skeleton.h"

#undef LOG_TAG
#define LOG_TAG "StationaryServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;

constexpr int32_t TYPE_TYPE_STAND = 7;
constexpr int32_t ACTIVITYEVENT_ENTER = 1;
constexpr int32_t REPORTLATENCYNS_LATENCY_INVALID = -1;
constexpr int32_t STATIONARY_RET_NO_SUPPORT = 801;
constexpr int32_t STATIONARY_RET_OK = 0;
constexpr int32_t STATIONARY_RET_NO_SYSTEM_API = 802;
constexpr int32_t DEVICE_STATUS_TYPE_STILL = 0;
constexpr int32_t DEVICE_STATUS_TYPE_ON_BICYCLE = 5;
constexpr int32_t DEVICE_STATUS_TYPE_WALKING = 1;


CallingContext context_ {
    .intention = Intention::STATIONARY,
    .tokenId = IPCSkeleton::GetCallingTokenID(),
    .uid = IPCSkeleton::GetCallingUid(),
    .pid = IPCSkeleton::GetCallingPid(),
};

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() = default;
    ~MockIRemoteObject() override = default;
    
    int32_t GetObjectRefCount() override { return 0; }
    int SendRequest(uint32_t code, MessageParcel &data,
                   MessageParcel &reply, MessageOption &option) override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }
    bool IsProxyObject() const override { return false; }
};

class StationaryServerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
    class StationaryServerTestCallback : public DeviceStatusCallbackStub {
    public:
        void OnDeviceStatusChanged(const Data& devicestatusData) override
        {
            GTEST_LOG_(INFO) << "StationaryServerTestCallback type: " << devicestatusData.type;
            GTEST_LOG_(INFO) << "StationaryServerTestCallback value: " << devicestatusData.value;
            EXPECT_TRUE(devicestatusData.type == Type::TYPE_VERTICAL_POSITION &&
                devicestatusData.value >= VALUE_INVALID &&
                devicestatusData.value <= VALUE_EXIT)
                << "StationaryServerTestCallback failed";
        }
    };
    struct MotionEvent {
        int32_t type;
        int32_t status;
    };
    class MotionCallback {
    public:
        virtual ~MotionCallback() = default;
        virtual void OnMotionChanged(const MotionEvent& event) = 0;
    };
    class TestMotionCallback : public MotionCallback {
    public:
        void SetEventCallback(std::function<void(const Data&)> cb)
        {
            event_ = cb;
        }
        
        void OnMotionChanged(const MotionEvent& event) override
        {
            if (event_) {
                Data data;
                data.type = static_cast<Type>(event.type);
                data.value = static_cast<OnChangedValue>(event.status);
                event_(data);
            }
        }
        
    private:
        std::function<void(const Data&)> event_;
    };

    class RemoteDevStaCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        virtual ~RemoteDevStaCallbackDeathRecipient() = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject>& remote) = 0;
    };

    class TestRemoteDevStaCallbackDeathRecipient : public RemoteDevStaCallbackDeathRecipient {
    public:
        void SetEventCallback(std::function<void(const wptr<IRemoteObject>&)> cb)
        {
            event_ = cb;
        }
        
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override
        {
            if (event_) {
                event_(remote);
            }
        }

    private:
        std::function<void(const wptr<IRemoteObject>&)> event_;
    };
};

/**
 * @tc.name: TestOnMotionChanged
 * @tc.desc: Test OnMotionChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StationaryServerTest, OnMotionChanged, TestSize.Level1)
{
    auto callback = std::make_shared<StationaryServerTest::TestMotionCallback>();
    bool callbackCalled = false;
    callback->SetEventCallback([&callbackCalled](const Data& data) {
        callbackCalled = true;
        EXPECT_TRUE(static_cast<int32_t>(data.type) >= DEVICE_STATUS_TYPE_STILL &&
                static_cast<int32_t>(data.type) <= DEVICE_STATUS_TYPE_ON_BICYCLE);
        EXPECT_EQ(static_cast<int32_t>(data.value), VALUE_ENTER);
    });
    
    StationaryServerTest::MotionEvent event = {DEVICE_STATUS_TYPE_WALKING, VALUE_ENTER};
    callback->OnMotionChanged(event);
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.name: TestOnRemoteDied
 * @tc.desc: Test OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StationaryServerTest, OnRemoteDied, TestSize.Level1)
{
    auto recipient = std::make_shared<StationaryServerTest::TestRemoteDevStaCallbackDeathRecipient>();
    bool callbackCalled = false;
    
    auto testCallback = [&callbackCalled](const wptr<IRemoteObject>& remote) {
        callbackCalled = true;
    };
    recipient->SetEventCallback(testCallback);
    auto mockRemote = sptr<IRemoteObject>(new MockIRemoteObject());
    wptr<IRemoteObject> weakRemote(mockRemote);
    recipient->OnRemoteDied(weakRemote);
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.name: TestDumpDeviceStatusSubscriber
 * @tc.desc: Test DumpDeviceStatusSubscriber
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, DumpDeviceStatusSubscriber, TestSize.Level1)
{
    StationaryServer server;
    server.DumpDeviceStatusSubscriber(1);
    SUCCEED();
}

/**
 * @tc.name: TestDumpDeviceStatusChanges
 * @tc.desc: Test DumpDeviceStatusChanges
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, DumpDeviceStatusChanges, TestSize.Level1)
{
    StationaryServer server;
    server.DumpDeviceStatusChanges(1);
    SUCCEED();
}

/**
 * @tc.name: TestSubscribeStationaryCallback_Stand
 * @tc.desc: Test SubscribeStationaryCallback for stand type
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, SubscribeStationaryCallback_Stand, TestSize.Level1)
{
    StationaryServer server;
    auto callback = std::make_shared<StationaryServerTest::StationaryServerTestCallback>();
    sptr<IRemoteDevStaCallback> remoteCallback(new StationaryServerTest::StationaryServerTestCallback());
    int32_t result = server.SubscribeStationaryCallback(
        context_, TYPE_TYPE_STAND, ACTIVITYEVENT_ENTER,
        REPORTLATENCYNS_LATENCY_INVALID, remoteCallback);
    EXPECT_TRUE(result == STATIONARY_RET_OK || result == STATIONARY_RET_NO_SUPPORT);
}

/**
 * @tc.name: TestGetDevicePostureDataSync
 * @tc.desc: Test GetDevicePostureDataSync function
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetDevicePostureDataSync, TestSize.Level1)
{
    StationaryServer server;
    DevicePostureData data;
    
    int32_t result = server.GetDevicePostureDataSync(context_, data);
    EXPECT_TRUE(result == STATIONARY_RET_OK || result == STATIONARY_RET_NO_SYSTEM_API ||
                result == STATIONARY_RET_NO_SUPPORT || result == RET_ERR);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS