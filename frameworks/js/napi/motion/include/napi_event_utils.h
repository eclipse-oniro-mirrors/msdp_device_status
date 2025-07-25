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

#ifndef NAPI_EVENT_UTILS_H
#define NAPI_EVENT_UTILS_H

#include <iostream>
#include <string>

namespace OHOS {
namespace Msdp {
class NapiEventUtils {
public:
    static int64_t AddProcessor();
    static void WriteEndEvent(const std::string& transId, const std::string& apiName, const int64_t beginTime,
        const int result, const int errCode);
    static int64_t GetSysClockTime();
};

} // namespace Msdp
} // namespace OHOS
#endif //MOTION_NAPI_H
