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
#include "gtest/gtest.h"
#include "ipc_skeleton.h"

#include "boomerang_callback_stub.h"
#include "boomerang_params.h"
#include "boomerang_server.h"
#include "default_params.h"
#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "devicestatus_dumper.h"
#include "devicestatus_manager.h"
#include "devicestatus_hisysevent.h"
#include "fi_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
BoomerangServer boomerang_;
int32_t FD { 5 };
inline constexpr size_t MAX_STRING_LEN{1024};
Intention intention_ { Intention::BOOMERANG };

} // namespace

class BoomerangServerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
    class BoomerangServerTestCallback : public BoomerangCallbackStub {
    public:
        void OnScreenshotResult(const BoomerangData& data);
    private:
        BoomerangData data_;
    };
};


void BoomerangServerTest::BoomerangServerTestCallback::OnScreenshotResult(const BoomerangData& data)
{
    GTEST_LOG_(INFO) << "BoomerangClientTestCallback type: " << data.type;
    GTEST_LOG_(INFO) << "BoomerangClientTestCallback status: " << data.status;
    EXPECT_FALSE(data.type == BoomerangType::BOOMERANG_TYPE_BOOMERANG &&
        data.status == BoomerangStatus::BOOMERANG_STATUS_NOT_SCREEN_SHOT)
        << "BoomerangClientTestCallback failed";
}
/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest001
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
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.Enable(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::ADD_BOOMERAMG_LISTENER, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest003
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
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::NOTIFY_METADATA, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::ENCODE_IMAGE, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest005
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
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::DECODE_IMAGE, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest006
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::REMOVE_BOOMERAMG_LISTENER, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest007
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
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.RemoveWatch(context, BoomerangRequestID::REMOVE_BOOMERAMG_LISTENER, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest008
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
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.RemoveWatch(context, BoomerangRequestID::DECODE_IMAGE, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest009
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(boomerang_.DumpCurrentDeviceStatus(FD));
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest010
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangType type { BOOMERANG_TYPE_INVALID };
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangServerTestCallback();
    SubscribeBoomerangParam param { type, bundleName, callback };
    ASSERT_TRUE(param.Marshalling(datas));
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::ADD_BOOMERAMG_LISTENER, datas, reply);
    EXPECT_EQ(ret, RET_OK);
}
/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest011
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangServerTestCallback();
    NotifyMetadataParam param { bundleName, callback };
    ASSERT_TRUE(param.Marshalling(datas));
    int32_t ret = boomerang_.AddWatch(context, BoomerangRequestID::NOTIFY_METADATA, datas, reply);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest015
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangServerTestCallback();
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    DecodeImageParam param { pixelMap, callback };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.RemoveWatch(context, BoomerangRequestID::DECODE_IMAGE, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest016
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.SetParam(context, BoomerangRequestID::SUBMIT_METADATA, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: BoomerangServerTest
 * @tc.desc: BoomerangServerTest017
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangServerTest, BoomerangServerTest017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
        CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = boomerang_.SetParam(context, BoomerangRequestID::DECODE_IMAGE, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS