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
#include <vector>

#include <gtest/gtest.h>

#include "cJSON.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "json_parser.h"

#undef LOG_TAG
#define LOG_TAG "JsonParserTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;

class JsonParserTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase(void);
};

void JsonParserTest::SetUpTestCase() {}

void JsonParserTest::TearDownTestCase() {}

void JsonParserTest::SetUp() {}

void JsonParserTest::TearDown() {}

/**
 * @tc.name: JsonParserTest_Constructor_001
 * @tc.desc: Test JsonParser constructor with nullptr jsonStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_Constructor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    ASSERT_EQ(parser.Get(), nullptr);
}

/**
 * @tc.name: JsonParserTest_Constructor_002
 * @tc.desc: Test JsonParser constructor with valid jsonStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_Constructor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": \"value\"}";
    JsonParser parser(jsonStr);
    ASSERT_NE(parser.Get(), nullptr);
}

/**
 * @tc.name: JsonParserTest_IsInteger_001
 * @tc.desc: Test IsInteger with nullptr json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_IsInteger_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    ASSERT_FALSE(parser.IsInteger(nullptr));
}

/**
 * @tc.name: JsonParserTest_ParseInt32_001
 * @tc.desc: Test ParseInt32 with nullptr json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseInt32_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    int32_t value = 0;
    ASSERT_EQ(parser.ParseInt32(nullptr, "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseInt32_002
 * @tc.desc: Test ParseInt32 with non-object json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseInt32_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "[1, 2, 3]";
    JsonParser parser(jsonStr);
    int32_t value = 0;
    ASSERT_EQ(parser.ParseInt32(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseInt32_003
 * @tc.desc: Test ParseInt32 with non-number jsonNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseInt32_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": \"value\"}";
    JsonParser parser(jsonStr);
    int32_t value = 0;
    ASSERT_EQ(parser.ParseInt32(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseInt32_004
 * @tc.desc: Test ParseInt32 with non-integer jsonNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseInt32_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": 123.45}";
    JsonParser parser(jsonStr);
    int32_t value = 0;
    ASSERT_EQ(parser.ParseInt32(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseInt32_005
 * @tc.desc: Test ParseInt32 with out-of-bounds integer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseInt32_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": 2147483648}";
    JsonParser parser(jsonStr);
    int32_t value = 0;
    ASSERT_EQ(parser.ParseInt32(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseInt32_006
 * @tc.desc: Test ParseInt32 with valid integer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseInt32_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": 123}";
    JsonParser parser(jsonStr);
    int32_t value = 0;
    ASSERT_EQ(parser.ParseInt32(parser.Get(), "key", value), RET_OK);
    ASSERT_EQ(value, 123);
}

/**
 * @tc.name: JsonParserTest_ParseString_001
 * @tc.desc: Test ParseString with nullptr json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    std::string value;
    ASSERT_EQ(parser.ParseString(nullptr, "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseString_002
 * @tc.desc: Test ParseString with non-object json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseString_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "[1, 2, 3]";
    JsonParser parser(jsonStr);
    std::string value;
    ASSERT_EQ(parser.ParseString(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseString_003
 * @tc.desc: Test ParseString with non-string jsonNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseString_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": 123}";
    JsonParser parser(jsonStr);
    std::string value;
    ASSERT_EQ(parser.ParseString(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseString_004
 * @tc.desc: Test ParseString with valid string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseString_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": \"value\"}";
    JsonParser parser(jsonStr);
    std::string value;
    ASSERT_EQ(parser.ParseString(parser.Get(), "key", value), RET_OK);
    ASSERT_EQ(value, "value");
}

/**
 * @tc.name: JsonParserTest_ParseBool_001
 * @tc.desc: Test ParseBool with nullptr json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseBool_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    bool value = false;
    ASSERT_EQ(parser.ParseBool(nullptr, "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseBool_002
 * @tc.desc: Test ParseBool with non-object json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseBool_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "[1, 2, 3]";
    JsonParser parser(jsonStr);
    bool value = false;
    ASSERT_EQ(parser.ParseBool(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseBool_003
 * @tc.desc: Test ParseBool with non-bool jsonNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseBool_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": 123}";
    JsonParser parser(jsonStr);
    bool value = false;
    ASSERT_EQ(parser.ParseBool(parser.Get(), "key", value), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseBool_004
 * @tc.desc: Test ParseBool with valid bool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseBool_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": true}";
    JsonParser parser(jsonStr);
    bool value = false;
    ASSERT_EQ(parser.ParseBool(parser.Get(), "key", value), RET_OK);
    ASSERT_TRUE(value);
}

/**
 * @tc.name: JsonParserTest_ParseStringArray_001
 * @tc.desc: Test ParseStringArray with nullptr json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseStringArray_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    std::vector<std::string> value;
    ASSERT_EQ(parser.ParseStringArray(nullptr, "key", value, 10), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseStringArray_002
 * @tc.desc: Test ParseStringArray with non-object json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseStringArray_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "[1, 2, 3]";
    JsonParser parser(jsonStr);
    std::vector<std::string> value;
    ASSERT_EQ(parser.ParseStringArray(parser.Get(), "key", value, 10), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseStringArray_003
 * @tc.desc: Test ParseStringArray with non-array jsonNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseStringArray_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": 123}";
    JsonParser parser(jsonStr);
    std::vector<std::string> value;
    ASSERT_EQ(parser.ParseStringArray(parser.Get(), "key", value, 10), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseStringArray_004
 * @tc.desc: Test ParseStringArray with non-string arrayItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseStringArray_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": [1, 2, 3]}";
    JsonParser parser(jsonStr);
    std::vector<std::string> value;
    ASSERT_EQ(parser.ParseStringArray(parser.Get(), "key", value, 10), RET_ERR);
}

/**
 * @tc.name: JsonParserTest_ParseStringArray_005
 * @tc.desc: Test ParseStringArray with valid array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseStringArray_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": [\"a\", \"b\", \"c\"]}";
    JsonParser parser(jsonStr);
    std::vector<std::string> value;
    ASSERT_EQ(parser.ParseStringArray(parser.Get(), "key", value, 10), RET_OK);
    ASSERT_EQ(value.size(), 3);
    ASSERT_EQ(value[0], "a");
    ASSERT_EQ(value[1], "b");
    ASSERT_EQ(value[2], "c");
}

/**
 * @tc.name: JsonParserTest_ParseStringArray_006
 * @tc.desc: Test ParseStringArray with array size larger than maxSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParserTest_ParseStringArray_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *jsonStr = "{\"key\": [\"a\", \"b\", \"c\", \"d\", \"e\"]}";
    JsonParser parser(jsonStr);
    std::vector<std::string> value;
    ASSERT_EQ(parser.ParseStringArray(parser.Get(), "key", value, 3), RET_OK);
    ASSERT_EQ(value.size(), 3);
    ASSERT_EQ(value[0], "a");
    ASSERT_EQ(value[1], "b");
    ASSERT_EQ(value[2], "c");
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS

//=================================================================
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
