/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ANI_BOOMERANG_H
#define ANI_BOOMERANG_H

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <string>

#include "taihe/runtime.hpp"
#include "pixel_map_taihe_ani.h"
#include "fi_log.h"
#include "boomerang_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace taihe;

typedef void (*EncodeImagePtr)(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, const std::string &content,
    std::shared_ptr<OHOS::Media::PixelMap> &resultPixelMap);
typedef void (*DecodeImagePtr)(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, std::string &content);

struct AniBoomerangEventListener {
    ani_ref onHandlerRef { nullptr };
};

class AniBoomerangEvent {
public:
    AniBoomerangEvent() = default;
    ~AniBoomerangEvent() = default;

    bool On(int32_t eventType, ani_ref handler, bool isOnce);
    bool Off(int32_t eventType);
    void OnEvent(int32_t eventType, int32_t value, bool isOnce);

protected:
    bool OffOnce(int32_t eventType, ani_ref handler);
    
    void ClearEventMap();
    bool RemoveAllCallback(int32_t eventType);
    bool SaveCallbackByEvent(int32_t eventType, ani_ref handler, bool isOnce,
        std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> events);
    bool IsNoExistCallback(std::list<std::shared_ptr<AniBoomerangEventListener>>,
        ani_ref handler, int32_t eventType);
    void SaveCallback(int32_t eventType, ani_ref onHandlerRef, bool isOnce);

    ani_env env_ { nullptr };
    ani_ref thisVarRef_ { nullptr };
    std::mutex mutex_;
    std::vector<BoomerangData> data_;
    std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> events_;
    std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> eventOnces_;
};

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
// #endif // DEVICESTATUS_EVENT_H
#endif
