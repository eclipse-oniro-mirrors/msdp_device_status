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

#include "accesstoken_kit.h"
#include <gmock/gmock.h>
#include "gtest/gtest.h"
#include "ipc_skeleton.h"

#include "boomerang_callback_stub.h"
#include "boomerang_server.h"
#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "devicestatus_dumper.h"
#include "devicestatus_manager.h"
#include "devicestatus_hisysevent.h"
#include "fi_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "parcel.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
BoomerangServer boomerang_;
int32_t FD { 1 };
inline constexpr size_t MAX_STRING_LEN{1024};
Intention intention_ { Intention::BOOMERANG };

static std::unique_ptr<Media::PixelMap> CreateEmptyPixelMap()
{
    Media::InitializationOptions initOptions;
    initOptions.size = {1080, 1920};
    initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
    initOptions.editable = true;
    std::unique_ptr<Media::PixelMap> pixmap = Media::PixelMap::Create(initOptions);
    return pixmap;
}

} // namespace

class BoomerangServerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
    class BoomerangServerTestCallback : public BoomerangCallbackStub {
    public:
    explicit BoomerangServerTestCallback() {}
    virtual ~BoomerangServerTestCallback() {};
    MOCK_METHOD(void, OnScreenshotResult, (const BoomerangData& data), (override));
    MOCK_METHOD(void, OnNotifyMetadata, (const std::string& metadata), (override));
    MOCK_METHOD(void, OnEncodeImageResult, (std::shared_ptr<Media::PixelMap> pixelMap), (override));
    MOCK_METHOD(void, EmitOnEvent, (BoomerangData& data));
    MOCK_METHOD(void, EmitOnMetadata, (std::string metadata));
    MOCK_METHOD(void, EmitOnEncodeImage, (std::shared_ptr<Media::PixelMap> pixelMap));
    };
};

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest001 for SubscribeCallback subCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangServerTest, BoomerangServerTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    char bundleName[MAX_STRING_LEN] = {0};
    int32_t type { BOOMERANG_TYPE_INVALID };
    sptr<IRemoteBoomerangCallback> subCallback { nullptr };
    int32_t ret = boomerang_.SubscribeCallback(context, type, bundleName, subCallback);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest02 for SubscribeCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    char bundleName[MAX_STRING_LEN] = {0};
    int32_t type { BOOMERANG_TYPE_BOOMERANG };
    sptr<IRemoteBoomerangCallback> subCallback = new (std::nothrow) BoomerangServerTestCallback();
    int32_t ret = boomerang_.SubscribeCallback(context, type, bundleName, subCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest003 for NotifyMetadataBindingEvent notifyCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> notifyCallback { nullptr };
    int32_t ret = boomerang_.NotifyMetadataBindingEvent(context, bundleName, notifyCallback);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest04 for NotifyMetadataBindingEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> notifyCallback = new (std::nothrow) BoomerangServerTestCallback();
    int32_t ret = boomerang_.NotifyMetadataBindingEvent(context, bundleName, notifyCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest005 for BoomerangEncodeImage encodeCallback and pixelMap is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    char metadata[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> encodeCallback = nullptr;
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    int32_t ret = boomerang_.BoomerangEncodeImage(context, pixelMap, metadata, encodeCallback);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest06 for BoomerangEncodeImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    string metadata = "test";
    sptr<IRemoteBoomerangCallback> encodeCallback = new (std::nothrow) BoomerangServerTestCallback();
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreateEmptyPixelMap();
    int32_t ret = boomerang_.BoomerangEncodeImage(context, pixelMap, metadata, encodeCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest007 for BoomerangDecodeImage decodeCallback and pixelMap is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteBoomerangCallback> decodeCallback { nullptr };
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    int32_t ret = boomerang_.BoomerangDecodeImage(context, pixelMap, decodeCallback);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest008 for BoomerangDecodeImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteBoomerangCallback> decodeCallback = new (std::nothrow) BoomerangServerTestCallback();
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreateEmptyPixelMap();
    int32_t ret = boomerang_.BoomerangDecodeImage(context, pixelMap, decodeCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest009 for UnsubscribeCallback unsubCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t type { BOOMERANG_TYPE_INVALID };
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> unsubCallback { nullptr };
    int32_t ret = boomerang_.UnsubscribeCallback(context, type, bundleName, unsubCallback);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest10 for UnsubscribeCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangType type { BOOMERANG_TYPE_BOOMERANG };
    sptr<IRemoteBoomerangCallback> unsubCallback = new (std::nothrow) BoomerangServerTestCallback();
    int32_t ret = boomerang_.UnsubscribeCallback(context, type, bundleName, unsubCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest11 for SubmitMetadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    string metadata = "";
    int32_t ret = boomerang_.SubmitMetadata(context, metadata);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest12 for SubmitMetadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest12, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    string metadata = "test";
    int32_t ret = boomerang_.SubmitMetadata(context, metadata);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest013 for DumpCurrentDeviceStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(boomerang_.DumpCurrentDeviceStatus(FD));
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest014 for DumpDeviceStatusSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(boomerang_.DumpDeviceStatusSubscriber(FD));
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest015 for DumpDeviceStatusChanges
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(boomerang_.DumpDeviceStatusChanges(FD));
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest16
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest16, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    boomerang_.ReportSensorSysEvent(context, 2, true);
    Data data = boomerang_.GetCache(context, Type::TYPE_STILL);
    EXPECT_EQ(data.status, Status::STATUS_INVALID);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS