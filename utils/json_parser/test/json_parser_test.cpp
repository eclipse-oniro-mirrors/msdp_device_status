/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <string>

#include "json_parser.h"
#include "util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
using namespace testing::ext;
using namespace OHOS;

static constexpr int32_t INT_VAL = 3;
static constexpr float FLOAT_VAL = 3.14;
static constexpr double DOUBLE_VAL = 3.141592653;
} // namespace

class JsonParserTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:IsIntegerTest_001
 * @tc.desc:Verify JsonParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, IsInteger_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(nullptr);
    EXPECT_FALSE(JsonParser::IsInteger(parser.Get()));
}

/**
 * @tc.name:JsonParserTest_001
 * @tc.desc:Verify JsonParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParser_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(R"({"Hello": 1})");
    JsonParser parser1(R"({"Hello": 2})");
    parser1 = std::move(parser);
    auto json = parser1.Get();
    EXPECT_NE(json, nullptr);
}

/**
 * @tc.name:JsonParserTest_002
 * @tc.desc:Verify JsonParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParser_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    JsonParser parser(R"({"Hello": 1})");
    JsonParser parser1 = std::move(parser);
    auto json = parser1.Get();
    EXPECT_NE(json, nullptr);
}

/**
 * @tc.name:ParseInt_001
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": 1})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_EQ(JsonParser::ParseInt32(parser.Get(), "Hello", value), RET_OK);
}

/**
 * @tc.name:ParseInt_002
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": "world"})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_NE(JsonParser::ParseInt32(parser.Get(), "Hello", value), RET_OK);
}

/**
 * @tc.name:ParseInt_003
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"integer": 42.13})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_NE(JsonParser::ParseInt32(parser.Get(), "integer", value), RET_OK);
}

/**
 * @tc.name:ParseInt_004
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"integer": 21474836480})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_EQ(JsonParser::ParseInt32(parser.Get(), "integer", value), RET_OK);
}

/**
 * @tc.name:ParseFloat_001
 * @tc.desc:Verify ParseFloat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseFloat_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"float": 3.14})";
    JsonParser parser(jsonData.c_str());
    float value = 0.0f;
    int32_t ret = JsonParser::ParseFloat(parser.Get(), "float", value);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FLOAT_EQ(value, FLOAT_VAL);
}

/**
 * @tc.name:ParseFloat_002
 * @tc.desc:Verify ParseFloat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseFloat_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"float": 3})";
    JsonParser parser(jsonData.c_str());
    float value = 0.0f;
    int32_t ret = JsonParser::ParseFloat(parser.Get(), "float", value);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FLOAT_EQ(value, static_cast<float>(INT_VAL));
}

/**
 * @tc.name:ParseFloat_003
 * @tc.desc:Verify ParseFloat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseFloat_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"float": "str"})";
    JsonParser parser(jsonData.c_str());
    float value = 0.0f;
    int32_t ret = JsonParser::ParseFloat(parser.Get(), "float", value);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:ParseFloat_004
 * @tc.desc:Verify ParseFloat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseFloat_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    float value = 0.0f;
    int32_t ret = JsonParser::ParseFloat(nullptr, "float", value);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:ParseDouble_001
 * @tc.desc:Verify ParseDouble
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseDouble_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"double": 3.141592653})";
    JsonParser parser(jsonData.c_str());
    double value = 0.0f;
    int32_t ret = JsonParser::ParseDouble(parser.Get(), "double", value);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_DOUBLE_EQ(value, DOUBLE_VAL);
}

/**
 * @tc.name:ParseDouble_002
 * @tc.desc:Verify ParseDouble
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseDouble_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"double": 3})";
    JsonParser parser(jsonData.c_str());
    double value = 0.0f;
    int32_t ret = JsonParser::ParseDouble(parser.Get(), "double", value);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_DOUBLE_EQ(value, static_cast<double>(INT_VAL));
}

/**
 * @tc.name:ParseDouble_003
 * @tc.desc:Verify ParseDouble
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseDouble_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"double": "str"})";
    JsonParser parser(jsonData.c_str());
    double value = 0.0f;
    int32_t ret = JsonParser::ParseDouble(parser.Get(), "double", value);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:ParseDouble_004
 * @tc.desc:Verify ParseDouble
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseDouble_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    double value = 0.0f;
    int32_t ret = JsonParser::ParseDouble(nullptr, "double", value);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name:ParseString_001
 * @tc.desc:Verify ParseString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": "Hello World"})";
    JsonParser parser(jsonData.c_str());
    std::string value;
    EXPECT_EQ(JsonParser::ParseString(parser.Get(), "Hello", value), RET_OK);
}

/**
 * @tc.name:ParseString_002
 * @tc.desc:Verify ParseString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseString_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": 1})";
    JsonParser parser(jsonData.c_str());
    std::string value;
    EXPECT_NE(JsonParser::ParseString(parser.Get(), "Hello", value), RET_OK);
}

/**
 * @tc.name:ParseStringArray_001
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": ["a", "b", "c"]})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_EQ(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 10), RET_OK);
}

/**
 * @tc.name:ParseStringArray_002
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": "World"})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_NE(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 10), RET_OK);
}

/**
 * @tc.name:ParseStringArray_003
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": [1, 2, 3]})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_NE(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 10), RET_OK);
}

/**
 * @tc.name:ParseStringArray_004
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Hello": ["a", "b", "c", "d"]})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_EQ(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 2), RET_OK);
}

/**
 * @tc.name:ParseBool_001
 * @tc.desc:Verify ParseBool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseBool_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Boolean": true})";
    JsonParser parser(jsonData.c_str());
    bool value;
    EXPECT_EQ(JsonParser::ParseBool(parser.Get(), "Boolean", value), RET_OK);
}

/**
 * @tc.name:ParseBool_002
 * @tc.desc:Verify ParseBool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseBool_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonData = R"({"Boolean": "true"})";
    JsonParser parser(jsonData.c_str());
    bool value;
    EXPECT_NE(JsonParser::ParseBool(parser.Get(), "Boolean", value), RET_OK);
}


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
} // DeviceStatus
} // namespace Msdp
} // namespace OHOS