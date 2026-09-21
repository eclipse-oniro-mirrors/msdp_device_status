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
 
#include "parcel.h"
namespace OHOS {
static int32_t g_expectInt32Values = 0;
static uint32_t expectUint32Values_ = 0;
static int64_t g_expectInt64Values = 0;
static uint64_t expectUint64Values_ = 0;
static std::string g_expectStrValues = "";
static bool g_expectBool = false;
static std::vector<std::string> g_expectVector;
thread_local bool g_mockWriteInt32Fail = false;
thread_local bool g_mockWriteStringFail = false;
thread_local bool g_mockReadInt32Fail = false;
thread_local bool g_mockReadStringFail = false;
void SetWriteInt32Fail(bool fail)
{
    g_mockWriteInt32Fail = fail;
}
void SetWriteStringFail(bool fail)
{
    g_mockWriteStringFail = fail;
}
void SetReadInt32Fail(bool fail)
{
    g_mockReadInt32Fail = fail;
}
void SetReadStringFail(bool fail)
{
    g_mockReadStringFail = fail;
}
void ResetMockFlags()
{
    g_mockWriteInt32Fail = false;
    g_mockWriteStringFail = false;
    g_mockReadInt32Fail = false;
    g_mockReadStringFail = false;
}
bool Parcel::WriteStringVector(const std::vector<std::string> &expectVector)
{
    g_expectVector = expectVector;
    return true;
}
 
bool Parcel::ReadStringVector(std::vector<std::string> *val)
{
    val = &g_expectVector;
    return true;
}
 
bool Parcel::WriteInt32(int32_t values)
{
    if (g_mockWriteInt32Fail) {
        return false;
    }
    g_expectInt32Values = values;
    return true;
}
 
bool Parcel::ReadInt32(int32_t &values)
{
    if (g_mockReadInt32Fail) {
        return false;
    }
    values = g_expectInt32Values;
    return true;
}
 
bool Parcel::WriteUint32(uint32_t values)
{
    expectUint32Values_ = values;
    return true;
}
 
bool Parcel::ReadUint32(uint32_t &values)
{
    values = expectUint32Values_;
    return true;
}
 
bool Parcel::ReadInt64(int64_t &values)
{
    values = g_expectInt64Values;
    return true;
}
 
bool Parcel::WriteInt64(int64_t values)
{
    g_expectInt64Values = values;
    return true;
}
 
bool Parcel::ReadUint64(uint64_t &values)
{
    values = expectUint64Values_;
    return true;
}
 
bool Parcel::WriteUint64(uint64_t values)
{
    expectUint64Values_ = values;
    return true;
}
 
bool Parcel::WriteString(const std::string &value)
{
    if (g_mockWriteStringFail) {
        return false;
    }
    g_expectStrValues = value;
    return true;
}
 
bool Parcel::ReadString(std::string &value)
{
    if (g_mockReadStringFail) {
        return false;
    }
    value = g_expectStrValues;
    return true;
}
 
bool Parcel::ReadBool(bool &value)
{
    value = g_expectBool;
    return true;
};
 
bool Parcel::WriteBool(bool value)
{
    g_expectBool = value;
    return true;
};
}  // namespace OHOS