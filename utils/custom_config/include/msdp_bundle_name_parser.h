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
 
#ifndef MSDP_BUNDLE_NAME_PARSER_H
#define MSDP_BUNDLE_NAME_PARSER_H
 
#include <shared_mutex>
#include <string>
#include <map>
 
#include "json_parser.h"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
class MsdpBundleNameParser {
public:
    MsdpBundleNameParser(const MsdpBundleNameParser&) = delete;
    MsdpBundleNameParser& operator=(const MsdpBundleNameParser&) = delete;
    static MsdpBundleNameParser& GetInstance();
    int32_t Init();
    std::string GetBundleName(const std::string &key);
 
private:
    struct MsdpBundleNameItem {
        std::string placeHolder;
        std::string bundleName;
    };
 
private:
    MsdpBundleNameParser() = default;
    ~MsdpBundleNameParser() = default;
 
    int32_t ParseBundleNameMap(const JsonParser &jsonParser);
    int32_t ParseBundleNameItem(const cJSON *json, MsdpBundleNameItem &bundleNameItem);
    void PrintBundleNames();
 
private:
    std::map<std::string, std::string> bundleNames_;
    std::shared_mutex lock_;
    std::atomic_bool isInitialized_ { false };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#define MSDP_BUNDLE_NAME_PARSER OHOS::Msdp::DeviceStatus::MsdpBundleNameParser::GetInstance()
#endif // MSDP_BUNDLE_NAME_PARSER_H