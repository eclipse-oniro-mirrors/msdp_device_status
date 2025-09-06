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

#include "specialinputdevice_fuzzer.h"

#include <cJSON.h>
#include "devicestatus_define.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "json_parser.h"

#include "special_input_device_parser.h"
#undef LOG_TAG
#define LOG_TAG "DDMAdapterFuzzTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr size_t STR_LEN = 255;

bool SpecialInputDeviceFuzzTest(FuzzedDataProvider &provider)
{
    std::string fileData = provider.ConsumeRandomLengthString(STR_LEN);
    std::string name = provider.ConsumeRandomLengthString(STR_LEN);
    std::string alias = provider.ConsumeRandomLengthString(STR_LEN);
    bool isPointerDevice = provider.ConsumeBool();
    JsonParser parser(fileData.c_str());
    SpecialInputDeviceParser::ExactlyMatchInputDevice dev1{
        .devName = name,
        .isMouse = provider.ConsumeBool(),
    };
    SpecialInputDeviceParser::ContainMatchInputDevice dev2{
        .isMouse = provider.ConsumeBool(),
    };
    SpecialInputDeviceParser::SpecialInputDevice dev3{
        .inputDevAlias = alias,
        .inputDevName = name,
    };
    cJSON *json = cJSON_GetObjectItemCaseSensitive(parser.Get(), "special_input_device");
    SpecialInputDeviceParser::GetInstance().ParseExactlyMatchItem(json, dev1);
    SpecialInputDeviceParser::GetInstance().ParseContainMatchItem(json, dev2);
    SpecialInputDeviceParser::GetInstance().ParseSpecialInputDeviceItem(json, dev3);
    SpecialInputDeviceParser::GetInstance().IsPointerDevice(name, isPointerDevice);
    SpecialInputDeviceParser::GetInstance().GetInputDevName(alias);
    SpecialInputDeviceParser::GetInstance().ParseExactlyMatch(parser);
    SpecialInputDeviceParser::GetInstance().ParseContainMatch(parser);
    SpecialInputDeviceParser::GetInstance().ParseSpecialInputDevice(parser);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    } 
    FuzzedDataProvider provider(data, size);
    OHOS::Msdp::DeviceStatus::SpecialInputDeviceFuzzTest(provider);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS