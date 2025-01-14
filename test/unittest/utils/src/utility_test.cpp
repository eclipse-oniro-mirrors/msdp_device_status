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

/**
 * @tc.name: UtityTest_Anonymize1_004
 * @tc.desc: Anonymisation of strings longer than 32 characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize1_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *id = "abcd123456efghijklmnopqrstuvwxyzabcd";
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id, Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("abcd1*****zabcd", Utility::Anonymize(id).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize1_005
 * @tc.desc: Enter null pointer network ID, anonymized to 6 '*'.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize1_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *id = nullptr;
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id, Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("**********", Utility::Anonymize(id).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize2_001
 * @tc.desc: Enter a normal 12-string network ID, anonymising the middle part to 6 '*' in addition to the first
 *  and last 4 characters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize2_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, NETWORK_ID.c_str(), Utility::Anonymize(NETWORK_ID).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual(EXPECT_ID.c_str(), Utility::Anonymize(NETWORK_ID).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize2_002
 * @tc.desc: Enter an empty network ID string, anonymized by 6 digits.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize2_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string id = "";
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id.c_str(), Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("**********", Utility::Anonymize(id).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize2_003
 * @tc.desc: Enter a network ID string less than 12 in length, anonymized to 6 *.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize2_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string id = "abcd123456";
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id.c_str(), Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("abcd1*****23456", Utility::Anonymize(id).c_str()));
}

/**
 * @tc.name: UtityTest_Anonymize2_004
 * @tc.desc: Anonymisation of strings longer than 32 characters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_Anonymize2_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string id = "abcd123456efghijklmnopqrstuvwxyzabcd";
    FI_HILOGI("%{public}d: Before anonymous processing, it is %{public}s, and after processing, it is %{public}s.",
        __LINE__, id.c_str(), Utility::Anonymize(id).c_str());
    ASSERT_NO_FATAL_FAILURE(Utility::IsEqual("abcd1*****zabcd", Utility::Anonymize(id).c_str()));
}

/**
 * @tc.name: UtityTest_DoesFileExist_001
 * @tc.desc: Check the file is or not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_DoesFileExist_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = "/system/etc/device_status/drag_icon/Copy_Drag.svg";
    bool isExist = Utility::DoesFileExist(filePath);
    ASSERT_TRUE(isExist);
}

/**
 * @tc.name: UtityTest_DoesFileExist_002
 * @tc.desc: Check the file is or not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_DoesFileExist_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = "";
    bool isExist = Utility::DoesFileExist(filePath);
    ASSERT_FALSE(isExist);
}

/**
 * @tc.name: UtityTest_DoesFileExist_003
 * @tc.desc: Check the file is or not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_DoesFileExist_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = "xxx/not_exist_file.txt";
    bool isExist = Utility::DoesFileExist(filePath);
    ASSERT_FALSE(isExist);
}

/**
 * @tc.name: UtityTest_DoesFileExist_004
 * @tc.desc: Check the file is or not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_DoesFileExist_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *filePath = nullptr;
    bool isExist = Utility::DoesFileExist(filePath);
    ASSERT_FALSE(isExist);
}

/**
 * @tc.name: UtityTest_IsEmpty_001
 * @tc.desc: Check string is or not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEmpty_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str = "isempty";
    bool isEmpty = Utility::IsEmpty(str);
    ASSERT_FALSE(isEmpty);
}

/**
 * @tc.name: UtityTest_IsEmpty_002
 * @tc.desc: Check string is or not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEmpty_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str = "";
    bool isEmpty = Utility::IsEmpty(str);
    ASSERT_TRUE(isEmpty);
}

/**
 * @tc.name: UtityTest_IsEmpty_003
 * @tc.desc: Check string is or not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEmpty_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str = nullptr;
    bool isEmpty = Utility::IsEmpty(str);
    ASSERT_TRUE(isEmpty);
}

/**
 * @tc.name: UtityTest_IsEqual_001
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = "abcde";
    const char *str2 = "abcde";
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_TRUE(isEqual);
}

/**
 * @tc.name: UtityTest_IsEqual_002
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = "abcde";
    const char *str2 = "edcba";
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_FALSE(isEqual);
}

/**
 * @tc.name: UtityTest_IsEqual_003
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = "";
    const char *str2 = "";
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_TRUE(isEqual);
}

/**
 * @tc.name: UtityTest_IsEqual_004
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = "abcde";
    const char *str2 = "";
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_FALSE(isEqual);
}

/**
 * @tc.name: UtityTest_IsEqual_005
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = "";
    const char *str2 = nullptr;
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_TRUE(isEqual);
}

/**
 * @tc.name: UtityTest_IsEqual_006
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = nullptr;
    const char *str2 = nullptr;
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_TRUE(isEqual);
}

/**
 * @tc.name: UtityTest_IsEqual_007
 * @tc.desc: Check string is or not equal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_IsEqual_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *str1 = "abcde";
    const char *str2 = nullptr;
    bool isEqual = Utility::IsEqual(str1, str2);
    ASSERT_FALSE(isEqual);
}

/**
 * @tc.name: UtityTest_ConcatAsString_001
 * @tc.desc: Splicing strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_ConcatAsString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str1 = "abcde";
    std::string str = Utility::ConcatAsString(str1);
    EXPECT_STREQ(str.c_str(), str1.c_str());
}

/**
 * @tc.name: UtityTest_ConcatAsString_002
 * @tc.desc: Splicing strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_ConcatAsString_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str1 = "abcde";
    std::string str2 = "fghij";
    std::string str = Utility::ConcatAsString(str1, str2);
    EXPECT_STREQ(str.c_str(), "abcdefghij");
}

/**
 * @tc.name: UtityTest_ConcatAsString_003
 * @tc.desc: Splicing strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_ConcatAsString_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str1 = "abcde";
    std::string str2 = "fghij";
    std::string str3 = "klmno";
    std::string str = Utility::ConcatAsString(str1, str2, str3);
    EXPECT_STREQ(str.c_str(), "abcdefghijklmno");
}

/**
 * @tc.name: UtityTest_ConcatAsString_004
 * @tc.desc: Splicing strings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_ConcatAsString_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str1 = "abcde";
    std::string str2 = "fghij";
    std::string str3 = "";
    std::string str = Utility::ConcatAsString(str1, str2, str3);
    EXPECT_STREQ(str.c_str(), "abcdefghij");
}

/**
 * @tc.name: UtityTest_RemoveSpace_001
 * @tc.desc: Remove string space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveSpace_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str = "abc de";
    Utility::RemoveSpace(str);
    EXPECT_STREQ(str.c_str(), "abcde");
}

/**
 * @tc.name: UtityTest_RemoveSpace_002
 * @tc.desc: Remove string space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveSpace_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str = "abcde";
    Utility::RemoveSpace(str);
    EXPECT_STREQ(str.c_str(), "abcde");
}

/**
 * @tc.name: UtityTest_RemoveSpace_003
 * @tc.desc: Remove string space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveSpace_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str = " abcde";
    Utility::RemoveSpace(str);
    EXPECT_STREQ(str.c_str(), "abcde");
}

/**
 * @tc.name: UtityTest_RemoveSpace_004
 * @tc.desc: Remove string space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveSpace_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str = "abcde ";
    Utility::RemoveSpace(str);
    EXPECT_STREQ(str.c_str(), "abcde");
}

/**
 * @tc.name: UtityTest_RemoveSpace_005
 * @tc.desc: Remove string space
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveSpace_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str = "    ";
    Utility::RemoveSpace(str);
    EXPECT_STREQ(str.c_str(), "");
}

/**
 * @tc.name: UtityTest_CopyNulstr_001
 * @tc.desc: Copy string to target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_CopyNulstr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char dest[] = "0";
    size_t size = SIZE1;
    char src[] = "abcdefghijklmnopqrst";
    size_t len = Utility::CopyNulstr(dest, size, src);
    EXPECT_EQ(len, size - 1);
}

/**
 * @tc.name: UtityTest_CopyNulstr_002
 * @tc.desc: Copy string to target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_CopyNulstr_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char *dest = nullptr;
    size_t size = SIZE2;
    char *src = nullptr;
    size_t len = Utility::CopyNulstr(dest, size, src);
    EXPECT_EQ(len, 0);
}

/**
 * @tc.name: UtityTest_CopyNulstr_003
 * @tc.desc: Copy string to target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_CopyNulstr_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char dest[] = {0};
    size_t size = SIZE2;
    char *src = nullptr;
    size_t len = Utility::CopyNulstr(dest, size, src);
    EXPECT_EQ(len, 0);
}

/**
 * @tc.name: UtityTest_CopyNulstr_004
 * @tc.desc: Copy string to target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_CopyNulstr_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char *dest = nullptr;
    size_t size = SIZE2;
    char src[] = "dadaaaaaaaddsadada";
    size_t len = Utility::CopyNulstr(dest, size, src);
    EXPECT_EQ(len, 0);
}

/**
 * @tc.name: UtityTest_GetSysClockTime_001
 * @tc.desc: Get system time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_GetSysClockTime_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t time = Utility::GetSysClockTime();
    EXPECT_NE(time, 0);
}

/**
 * @tc.name: UtityTest_StartWith1_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith1_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *exampleStr = "HelloWorld";
    const char *examplePrefix = "Hello";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_StartWith1_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith1_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *exampleStr = "HelloWorld";
    const char *examplePrefix = "HelloWorld";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_StartWith1_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith1_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *exampleStr = "HelloWorld";
    const char *examplePrefix = "";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_StartWith1_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith1_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *exampleStr = "Hello";
    const char *examplePrefix = "HelloWorld";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_StartWith1_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith1_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *exampleStr = "";
    const char *examplePrefix = "HelloWorld";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_StartWith1_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith1_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *exampleStr = "";
    const char *examplePrefix = "";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_StartWith2_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith2_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string exampleStr = "abc12345";
    std::string examplePrefix = "abc";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_StartWith2_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith2_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string exampleStr = "abc";
    std::string examplePrefix = "abc";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_StartWith2_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith2_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string exampleStr = "abc12345";
    std::string examplePrefix = "";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_StartWith2_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith2_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string exampleStr = "abc";
    std::string examplePrefix = "abcdefg";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_StartWith2_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith2_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string exampleStr = "";
    std::string examplePrefix = "abc";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: UtityTest_StartWith2_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_StartWith2_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string exampleStr = "";
    std::string examplePrefix = "";
    bool ret = Utility::StartWith(exampleStr, examplePrefix);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars1_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars1_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char path2[] = "abcd";
    Utility::RemoveTrailingChars('d', path2);
    ASSERT_STREQ(path2, "abc");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars1_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars1_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char path2[] = "abcd";
    Utility::RemoveTrailingChars('d', path2);
    ASSERT_STREQ(path2, "abc");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars1_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars1_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char path2[] = "abacda";
    Utility::RemoveTrailingChars('a', path2);
    ASSERT_STREQ(path2, "abacd");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars1_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars1_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char path2[] = "abacda";
    Utility::RemoveTrailingChars('f', path2);
    ASSERT_STREQ(path2, "abacda");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars1_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars1_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char path2[] = "";
    Utility::RemoveTrailingChars('f', path2);
    ASSERT_STREQ(path2, "");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars2_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars2_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string path1 = "cd";
    std::string path2 = "abcd";
    Utility::RemoveTrailingChars(path1, path2);
    ASSERT_STREQ(path2.c_str(), "ab");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars2_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars2_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string path1 = "c";
    std::string path2 = "abdc";
    Utility::RemoveTrailingChars(path1, path2);
    ASSERT_STREQ(path2.c_str(), "abd");
}


/**
 * @tc.name: UtityTest_RemoveTrailingChars2_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars2_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string path1 = "a";
    std::string path2 = "abacda";
    Utility::RemoveTrailingChars(path1, path2);
    ASSERT_STREQ(path2.c_str(), "abacd");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars2_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars2_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string path1 = "e";
    std::string path2 = "abc";
    Utility::RemoveTrailingChars(path1, path2);
    ASSERT_STREQ(path2.c_str(), "abc");
}

/**
 * @tc.name: UtityTest_RemoveTrailingChars2_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilityTest, UtityTest_RemoveTrailingChars2_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string path1 = "";
    std::string path2 = "abc";
    Utility::RemoveTrailingChars(path1, path2);
    ASSERT_STREQ(path2.c_str(), "abc");
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
