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

#ifndef INPUT_ADAPTER_TEST_H
#define INPUT_ADAPTER_TEST_H

#include <gtest/gtest.h>

#include "devicestatus_define.h"
#include "input_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class MockHapToken {
public:
    explicit MockHapToken(
        const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp = true);
    ~MockHapToken();
private:
    uint64_t selfToken_;
    uint32_t mockToken_;
};

class MockNativeToken {
public:
    explicit MockNativeToken(const std::string& process);
    ~MockNativeToken();
private:
    uint64_t selfToken_;
};
class InputAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INPUT_ADAPTER_TEST_H
