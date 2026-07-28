/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CAR_AWARENESS_TYPE_INNER_H
#define CAR_AWARENESS_TYPE_INNER_H

#include <map>
#include <string>
#include <variant>

namespace OHOS {
namespace Msdp {

// 如需新增类型, 在后面插入
using ValueObj = std::variant<bool, int32_t, std::string>;

typedef struct CarAwarenessOption {
    std::map<std::string, std::map<std::string, ValueObj>> entityInfo;
    CarAwarenessOption() = default;
} CarAwarenessOption;

typedef struct CarAwarenessEvent {
    int32_t type = -1;
    std::string eventData;
} CarAwarenessEvent;
} // namespace Msdp
} // namespace OHOS

#endif