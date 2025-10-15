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
 
#include "msdp_bundle_name_parser.h"
 
#include "devicestatus_define.h"
 
#include "util.h"
 
#include <cJSON.h>
 
#undef LOG_TAG
#define LOG_TAG "MsdpBundleNameParser"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr std::string_view bundleNameConfigDir { "/etc/multimodalinput/bundle_name_config.json" };
constexpr int32_t maxJsonArraySize { 100 };
} // namespace
 
MsdpBundleNameParser& MsdpBundleNameParser::GetInstance()
{
    static MsdpBundleNameParser instance;
    return instance;
}
 
int32_t MsdpBundleNameParser::Init()
{
    CALL_DEBUG_ENTER;
    static std::once_flag flag;
    static int32_t ret = RET_OK;
    std::call_once(flag, [&]() {
        std::string jsonStr = ReadJsonFile(std::string(bundleNameConfigDir));
        if (jsonStr.empty()) {
            FI_HILOGE("Read bundleName failed");
            ret = RET_ERR;
        }
        JsonParser parser(jsonStr.c_str());
        if (!cJSON_IsObject(parser.Get())) {
            FI_HILOGE("Not valid object");
            ret = RET_ERR;
        }
        if (ParseBundleNameMap(parser) != RET_OK) {
            FI_HILOGE("ParseBundleNameMap failed");
            ret = RET_ERR;
        }
        PrintBundleNames();
    });
    return ret;
}
 
std::string MsdpBundleNameParser::GetBundleName(const std::string &key)
{
    if (Init() != RET_OK) {
        FI_HILOGE("Init failed");
        return "";
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (bundleNames_.find(key) != bundleNames_.end()) {
        return bundleNames_[key];
    }
    FI_HILOGW("No %{public}s matched.", key.c_str());
    return "";
}
 
int32_t MsdpBundleNameParser::ParseBundleNameMap(const JsonParser &jsonParser)
{
    cJSON *bundleNameMapJson = cJSON_GetObjectItemCaseSensitive(jsonParser.Get(), "bundle_name_map");
    if (!cJSON_IsArray(bundleNameMapJson)) {
        FI_HILOGE("bundleNameMapJson is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(bundleNameMapJson);
    if (arraySize > maxJsonArraySize) {
        FI_HILOGW("arraySize is too much, truncate it");
    }
    for (int32_t i = 0; i < std::min(arraySize, maxJsonArraySize); i++) {
        cJSON* bundleNameItemJson = cJSON_GetArrayItem(bundleNameMapJson, i);
        CHKPC(bundleNameItemJson);
        MsdpBundleNameItem bundleNameItem;
        if (ParseBundleNameItem(bundleNameItemJson, bundleNameItem) != RET_OK) {
            FI_HILOGE("ParseBundleNameItem failed");
            continue;
        }
        std::unique_lock<std::shared_mutex> lock(lock_);
        bundleNames_.insert({ bundleNameItem.placeHolder, bundleNameItem.bundleName });
    }
    return RET_OK;
}
 
int32_t MsdpBundleNameParser::ParseBundleNameItem(const cJSON *json, MsdpBundleNameItem &bundleNameItem)
{
    if (JsonParser::ParseString(json, "placeholder", bundleNameItem.placeHolder) != RET_OK) {
        FI_HILOGW("Parse placeholder failed");
        return RET_ERR;
    }
    if (JsonParser::ParseString(json, "bundle_name", bundleNameItem.bundleName) != RET_OK) {
        FI_HILOGW("Parse bundle_name failed");
        return RET_ERR;
    }
    return RET_OK;
}
 
void MsdpBundleNameParser::PrintBundleNames()
{
    CALL_INFO_TRACE;
    std::shared_lock<std::shared_mutex> lock(lock_);
    for (const auto &bundleName: bundleNames_) {
        FI_HILOGI("key:%{public}s -> value:%{public}s", bundleName.first.c_str(), bundleName.second.c_str());
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS