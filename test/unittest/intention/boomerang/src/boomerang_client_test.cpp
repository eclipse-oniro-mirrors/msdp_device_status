/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <future>
#include <optional>

#include <unistd.h>
#include <utility>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "boomerang_callback_stub.h"
#include "boomerang_client.h"
#include "iremote_boomerang_callback.h"
#include "boomerang_params.h"
#include "default_params.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "i_hotarea_listener.h"
#include "i_event_listener.h"
#include "i_coordination_listener.h"


#undef LOG_TAG
#define LOG_TAG "BoomerangClientTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace testing;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
inline constexpr size_t MAX_STRING_LEN{1024};
// const std::string SYSTEM_BASIC { "system_basic" };
} // namespace

static std::unique_ptr<Media::PixelMap> CreateEmptyPixelMap()
{
    Media::InitializationOptions initOptions;
    initOptions.size = {1080, 1920};
    initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
    initOptions.editable = true;
    std::unique_ptr<Media::PixelMap> pixmap = Media::PixelMap::Create(initOptions);
    return pixmap;
}

class BoomerangClientTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
    class BoomerangClientTestCallback : public BoomerangCallbackStub {
    public:
    // void OnScreenshotResult(const BoomerangData& data);
    private:
    BoomerangData data_;
    };
};

void BoomerangClientTest::SetUpTestCase() {}

void BoomerangClientTest::TearDownTestCase() {}

void BoomerangClientTest::SetUp() {}

void BoomerangClientTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class TestEventListener final : public IEventListener {
public:
    TestEventListener() : IEventListener() {};
    ~TestEventListener() = default;

    void OnMouseLocationEvent(const std::string &networkId, const Event &event) override
    {
        (void) networkId;
        (void) event;
    };
};

/**
 * @tc.name: BoomerangClientTest_001
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangClient boomerangClient;
    int32_t ret = boomerangClient.SubscribeCallback(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
    ret = boomerangClient.UnsubscribeCallback(BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_002
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangClient boomerangClient;
    int32_t ret = boomerangClient.SubscribeCallback(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ret = boomerangClient.NotifyMetadataBindingEvent(bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_003
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metadata = "test";
    BoomerangClient boomerangClient;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    char bundleName[MAX_STRING_LEN] = {0};
    int32_t ret = boomerangClient.SubscribeCallback(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
    ret = boomerangClient.SubmitMetadata(metadata);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_004
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metadata = "test";
    BoomerangClient boomerangClient;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreateEmptyPixelMap();
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    int32_t ret = boomerangClient.BoomerangEncodeImage(pixelMap, metadata, callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_005
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metadata = "test";
    BoomerangClient boomerangClient;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreateEmptyPixelMap();
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    int32_t ret = boomerangClient.BoomerangDecodeImage(pixelMap, callback);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_006
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteBoomerangCallback> callback1 = new (std::nothrow) BoomerangClientTestCallback();
    sptr<IRemoteBoomerangCallback> callback2 = nullptr;
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangClient boomerangClient;
    int32_t ret = boomerangClient.SubscribeCallback(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback1);
    ASSERT_EQ(ret, RET_OK);
    ret = boomerangClient.UnsubscribeCallback(BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback2);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_007
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteBoomerangCallback> callback1 = new (std::nothrow) BoomerangClientTestCallback();
    sptr<IRemoteBoomerangCallback> callback2 = nullptr;
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangClient boomerangClient;
   int32_t ret = boomerangClient.SubscribeCallback(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback1);
    ASSERT_EQ(ret, RET_OK);
    ret = boomerangClient.NotifyMetadataBindingEvent(bundleName, callback2);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_008
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metadata;
    BoomerangClient boomerangClient;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    char bundleName[MAX_STRING_LEN] = {0};
    int32_t ret = boomerangClient.SubscribeCallback(
        BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
    ret = boomerangClient.SubmitMetadata(metadata);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangClientTest_009
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metadata;
    BoomerangClient boomerangClient;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreateEmptyPixelMap();
    sptr<IRemoteBoomerangCallback> callback = nullptr;
    int32_t ret = boomerangClient.BoomerangEncodeImage(pixelMap, metadata, callback);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: BoomerangClientTest_010
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metadata;
    BoomerangClient boomerangClient;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreateEmptyPixelMap();
    sptr<IRemoteBoomerangCallback> callback = nullptr;
    int32_t ret = boomerangClient.BoomerangDecodeImage(pixelMap, callback);
    ASSERT_NE(ret, RET_OK);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
