/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <vector>

#include <gtest/gtest.h>

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "UtilityTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string STR_INFO { "abc12345" };
const std::string STR_PREFIX { "abc" };
const std::string NETWORK_ID = { "abcd123456ef" };
const std::string EXPECT_ID = { "abcd1*****456ef" };
const std::string COPY_DRAG_PATH { "/system/etc/device_status/drag_icon/Copy_Drag.svg" };
constexpr int32_t FILE_SIZE_MAX { 0x5000 };
constexpr size_t SIZE1 {10};
constexpr size_t SIZE2 {20};
} // namespace

class UtilityTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase(void);
};

void UtilityTest::SetUpTestCase() {}

void UtilityTest::TearDownTestCase() {}

void UtilityTest::SetUp() {}

void UtilityTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: UtityTest_IsInteger_001
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "0";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_002
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "123";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_003
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = " 0";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_004
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "-0";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_005
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "-1";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_006
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "-10";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_007
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "123";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_008
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "-123";
    bool ret = Utility::IsInteger(target);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_009
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "0123";
    bool ret = Utility::IsInteger(target);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_010
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "A01";
    bool ret = Utility::IsInteger(target);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_011
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest,  UtityTest_IsInteger_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = "A-10";
    bool ret = Utility::IsInteger(target);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_012
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = " 123A";
    bool ret = Utility::IsInteger(target);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_IsInteger_013
 * @tc.desc: Checks whether a string is an integer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsInteger_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string target = " 123 A";
    bool ret = Utility::IsInteger(target);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_GetFileSize1_001
 * @tc.desc: Enter an existing file and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize1_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ssize_t fileSize = Utility::GetFileSize(COPY_DRAG_PATH.c_str());
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    } else {
        FI_HILOGI("%{public}d: File is %{public}s, and file size is %{public}zd.",
            __LINE__, COPY_DRAG_PATH.c_str(), fileSize);
    }
    EXPECT_GT(fileSize, 0);
}

/**
 * @tc.name: UtityTest_GetFileSize1_002
 * @tc.desc: Enter a nonexistent file and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize1_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = "xxx/not_exist_file.txt";
    ssize_t fileSize = Utility::GetFileSize(filePath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    }
    EXPECT_EQ(fileSize, 0);
}

/**
 * @tc.name: UtityTest_GetFileSize1_003
 * @tc.desc: Enter an empty string and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize1_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = "";
    ssize_t fileSize = Utility::GetFileSize(filePath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    }
    EXPECT_EQ(fileSize, 0);
}

/**
 * @tc.name: UtityTest_GetFileSize1_004
 * @tc.desc: Enter a null pointer and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize1_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = nullptr;
    ssize_t fileSize = Utility::GetFileSize(filePath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    }
    EXPECT_EQ(fileSize, 0);
}

/**
 * @tc.name: UtityTest_GetFileSize2_001
 * @tc.desc: Enter an existing file and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize2_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ssize_t fileSize = Utility::GetFileSize(COPY_DRAG_PATH);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    } else {
        FI_HILOGI("%{public}d: File is %{public}s, and file size is %{public}zd.",
            __LINE__, COPY_DRAG_PATH.c_str(), fileSize);
    }
    EXPECT_GT(fileSize, 0);
}

/**
 * @tc.name: UtityTest_GetFileSize2_002
 * @tc.desc: Enter a nonexistent file and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize2_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string filePath = "xxx/not_exist_file.txt";
    ssize_t fileSize = Utility::GetFileSize(filePath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    }
    EXPECT_EQ(fileSize, 0);
}

/**
 * @tc.name: UtityTest_GetFileSize_003
 * @tc.desc: Enter an empty string and read the length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetFileSize2_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string filePath = "";
    ssize_t fileSize = Utility::GetFileSize(filePath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGW("File size out of read range, filseSize: %{public}zd.", fileSize);
    }
    EXPECT_EQ(fileSize, 0);
}

/**
 * @tc.name: UtityTest_Anonymize1_001
 * @tc.desc: Enter a normal 12-string network ID, anonymising the middle part to 6 '*' in addition to the first
 *  and last 4 characters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize1_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
         __LINE__, NETWORK_ID.c_str(), Utility::Anonymize(NETWORK_ID).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual(EXPECT_ID.c_str(), Utility::Anonymize(NETWORK_ID).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize1_002
 * @tc.desc: Enter an empty network ID string, anonymized by 6 digits.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize1_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *id = "";
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id, Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("**********", Utility::Anonymize(id).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize1_003
 * @tc.desc: Enter a network ID string less than 12 in length, anonymized to 6 *.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize1_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *id = "abcd123456";
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id, Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("abcd1*****23456", Utility::Anonymize(id).c_str()));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS