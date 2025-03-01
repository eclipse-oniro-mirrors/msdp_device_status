/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef BOOMERANG_DATA_H
#define BOOMERANG_DATA_H

#include <string>
#include "pixel_map.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr int32_t SCREENSHOT_STATUS { 1 };
enum BoomerangType {
    BOOMERANG_TYPE_INVALID = -1,
    BOOMERANG_TYPE_BOOMERANG,
    BOOMERANG_TYPE_MAX
};

enum BoomerangStatus {
    BOOMERANG_STATUS_INVALID = -1,
    BOOMERANG_STATUS_NOT_SCREEN_SHOT,
    BOOMERANG_STATUS_SCREEN_SHOT,
};

struct BoomerangData {
    BoomerangType type { BOOMERANG_TYPE_INVALID };
    BoomerangStatus status { BOOMERANG_STATUS_INVALID };
    
    bool operator !=(const BoomerangData &r) const
    {
        if (type == r.type && status - r.status) {
            return false;
        }
        return true;
    }
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_DATA_H