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

#include "behavior_awareness_callback_proxy.h"
#include "behavior_awareness_callback_stub.h"
#include "behavior_awareness_data.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "fi_log.h"
#include "message_parcel.h"
#include "message_option.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessCallbackTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {

using namespace testing::ext;

class TestCallbackStub : public BehaviorAwarenessCallbackStub {
public:
    void OnBehaviorAwareness(const PerceptionEventData &event) override
    {
        receivedEvents_.push_back(event);
    }
    std::vector<PerceptionEventData> receivedEvents_;
};

class FailingCallbackStub : public BehaviorAwarenessCallbackStub {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }
};

static PerceptionEventData MakeEvent(const std::string &id)
{
    return PerceptionEventData {
        .perceptionEventId = id,
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 80,
        .generateTime = 1000,
        .payload = "test-payload",
    };
}

static void WriteEventToParcel(MessageParcel &data, const PerceptionEventData &event)
{
    data.WriteString(event.perceptionEventId);
    data.WriteInt32(static_cast<int32_t>(event.domain));
    data.WriteInt32(event.confidence);
    data.WriteInt64(event.generateTime);
    data.WriteString(event.payload);
}

/* ==================== BehaviorAwarenessCallbackStub ==================== */

class BehaviorAwarenessCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        stub_ = sptr<TestCallbackStub>::MakeSptr();
        ASSERT_NE(stub_, nullptr);
    }
    void TearDown() override {}
    sptr<TestCallbackStub> stub_;
};

HWTEST_F(BehaviorAwarenessCallbackStubTest, OnRemoteRequest_DescriptorMismatch, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.msdp.SomeOtherDescriptor");
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IRemoteBehaviorAwarenessCallback::BEHAVIOR_AWARENESS_CHANGE),
        data, reply, option);
    EXPECT_EQ(ret, E_DEVICESTATUS_GET_SERVICE_FAILED);
}

HWTEST_F(BehaviorAwarenessCallbackStubTest, OnRemoteRequest_ValidEvent, TestSize.Level1)
{
    PerceptionEventData event = MakeEvent("evt-001");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BehaviorAwarenessCallbackStub::GetDescriptor());
    WriteEventToParcel(data, event);

    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IRemoteBehaviorAwarenessCallback::BEHAVIOR_AWARENESS_CHANGE),
        data, reply, option);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_EQ(stub_->receivedEvents_.size(), 1u);
    EXPECT_EQ(stub_->receivedEvents_[0].perceptionEventId, "evt-001");
    EXPECT_EQ(stub_->receivedEvents_[0].confidence, 80);
    EXPECT_EQ(stub_->receivedEvents_[0].payload, "test-payload");
}

HWTEST_F(BehaviorAwarenessCallbackStubTest, OnRemoteRequest_UnknownCode, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BehaviorAwarenessCallbackStub::GetDescriptor());
    int32_t ret = stub_->OnRemoteRequest(9999, data, reply, option);
    EXPECT_NE(ret, RET_OK);
    EXPECT_EQ(stub_->receivedEvents_.size(), 0u);
}

HWTEST_F(BehaviorAwarenessCallbackStubTest, OnBehaviorAwarenessStub_EmptyPayload, TestSize.Level1)
{
    PerceptionEventData event {
        .perceptionEventId = "evt-empty",
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 0,
        .generateTime = 0,
        .payload = "",
    };
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BehaviorAwarenessCallbackStub::GetDescriptor());
    WriteEventToParcel(data, event);

    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IRemoteBehaviorAwarenessCallback::BEHAVIOR_AWARENESS_CHANGE),
        data, reply, option);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_EQ(stub_->receivedEvents_.size(), 1u);
    EXPECT_EQ(stub_->receivedEvents_[0].perceptionEventId, "evt-empty");
    EXPECT_EQ(stub_->receivedEvents_[0].confidence, 0);
}

/* ==================== BehaviorAwarenessCallbackProxy ==================== */

class BehaviorAwarenessCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        stub_ = sptr<TestCallbackStub>::MakeSptr();
        ASSERT_NE(stub_, nullptr);
        proxy_ = new BehaviorAwarenessCallbackProxy(stub_->AsObject());
        ASSERT_NE(proxy_, nullptr);
    }
    void TearDown() override {}
    sptr<TestCallbackStub> stub_;
    sptr<BehaviorAwarenessCallbackProxy> proxy_;
};

HWTEST_F(BehaviorAwarenessCallbackProxyTest, OnBehaviorAwareness_ProxyToStub, TestSize.Level1)
{
    PerceptionEventData event = MakeEvent("proxy-evt-001");
    stub_->receivedEvents_.clear();
    proxy_->OnBehaviorAwareness(event);
    ASSERT_EQ(stub_->receivedEvents_.size(), 1u);
    EXPECT_EQ(stub_->receivedEvents_[0].perceptionEventId, "proxy-evt-001");
    EXPECT_EQ(stub_->receivedEvents_[0].confidence, 80);
    EXPECT_EQ(stub_->receivedEvents_[0].payload, "test-payload");
    EXPECT_EQ(stub_->receivedEvents_[0].generateTime, 1000);
}

HWTEST_F(BehaviorAwarenessCallbackProxyTest, OnBehaviorAwareness_MultipleCalls, TestSize.Level1)
{
    stub_->receivedEvents_.clear();
    proxy_->OnBehaviorAwareness(MakeEvent("proxy-evt-a"));
    proxy_->OnBehaviorAwareness(MakeEvent("proxy-evt-b"));
    proxy_->OnBehaviorAwareness(MakeEvent("proxy-evt-c"));
    ASSERT_EQ(stub_->receivedEvents_.size(), 3u);
    EXPECT_EQ(stub_->receivedEvents_[0].perceptionEventId, "proxy-evt-a");
    EXPECT_EQ(stub_->receivedEvents_[1].perceptionEventId, "proxy-evt-b");
    EXPECT_EQ(stub_->receivedEvents_[2].perceptionEventId, "proxy-evt-c");
}

HWTEST_F(BehaviorAwarenessCallbackProxyTest, OnBehaviorAwareness_EmptyPayload, TestSize.Level1)
{
    PerceptionEventData event {
        .perceptionEventId = "proxy-empty",
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 100,
        .generateTime = 9999,
        .payload = "",
    };
    stub_->receivedEvents_.clear();
    proxy_->OnBehaviorAwareness(event);
    ASSERT_EQ(stub_->receivedEvents_.size(), 1u);
    EXPECT_EQ(stub_->receivedEvents_[0].perceptionEventId, "proxy-empty");
    EXPECT_EQ(stub_->receivedEvents_[0].confidence, 100);
    EXPECT_EQ(stub_->receivedEvents_[0].generateTime, 9999);
}

HWTEST_F(BehaviorAwarenessCallbackProxyTest, OnBehaviorAwareness_SendRequestFails, TestSize.Level1)
{
    auto failingStub = sptr<FailingCallbackStub>::MakeSptr();
    ASSERT_NE(failingStub, nullptr);
    auto failingProxy = new BehaviorAwarenessCallbackProxy(failingStub->AsObject());
    ASSERT_NE(failingProxy, nullptr);
    PerceptionEventData event = MakeEvent("proxy-fail");
    failingProxy->OnBehaviorAwareness(event);
}

} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
