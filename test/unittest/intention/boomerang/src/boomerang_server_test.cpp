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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS