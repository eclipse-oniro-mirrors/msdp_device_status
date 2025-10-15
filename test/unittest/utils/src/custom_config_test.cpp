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
#include <vector>
 
#include <gtest/gtest.h>
 
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "msdp_bundle_name_parser.h"
 
#undef LOG_TAG
#define LOG_TAG "CustomConfigTest"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
} // namespace
 
class CustomConfigTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase(void);
};
 
void CustomConfigTest::SetUpTestCase() {}
 
void CustomConfigTest::TearDownTestCase() {}
 
void CustomConfigTest::SetUp() {}
 
void CustomConfigTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}
 
/**
 * @tc.name: CustomConfigTest_Init
 * @tc.desc: Msdp bundle name parser.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CustomConfigTest, CustomConfigTest_Init, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = MSDP_BUNDLE_NAME_PARSER.Init();
    ASSERT_EQ(ret, RET_OK);
    ret = MSDP_BUNDLE_NAME_PARSER.Init();
    ASSERT_EQ(ret, RET_OK);
}
 
/**
 * @tc.name: CustomConfigTest_GetBundleName
 * @tc.desc: Msdp bundle name parser.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CustomConfigTest, CustomConfigTest_GetBundleName, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string ret = MSDP_BUNDLE_NAME_PARSER.GetBundleName("test");
    ASSERT_EQ(ret, "");
    MSDP_BUNDLE_NAME_PARSER.GetBundleName("DEVICE_COLLABORATION");
}
 
/**
 * @tc.name: CustomConfigTest_ParseBundleNameMap
 * @tc.desc: Msdp bundle name parser.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CustomConfigTest, CustomConfigTest_ParseBundleNameMap, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser jsonParser("test");
    int32_t ret = MSDP_BUNDLE_NAME_PARSER.ParseBundleNameMap(jsonParser);
    ASSERT_EQ(ret, RET_ERR);
}
 
/**
 * @tc.name: CustomConfigTest_ParseBundleNameItem
 * @tc.desc: Msdp bundle name parser.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CustomConfigTest, CustomConfigTest_ParseBundleNameItem, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    cJSON* json { nullptr };
    MsdpBundleNameParser::MsdpBundleNameItem msdpBundleNameItem;
    int32_t ret = MSDP_BUNDLE_NAME_PARSER.ParseBundleNameItem(json, msdpBundleNameItem);
    ASSERT_EQ(ret, RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS