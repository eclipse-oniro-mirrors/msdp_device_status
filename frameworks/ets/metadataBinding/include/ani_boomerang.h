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
#include <string>
#include <vector>

#include "boomerang_data.h"
#include "fi_log.h"
#include "pixel_map_taihe_ani.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace taihe;

struct AniBoomerangEventListener {
    ani_ref onHandlerRef { nullptr };
};

class AniBoomerangCommon {
public:
    AniBoomerangCommon() = default;
    ~AniBoomerangCommon() = default;
    static std::shared_ptr<AniBoomerangCommon> GetInstance();

    static ani_vm* GetAniVm(ani_env* env);
    static ani_env* GetAniEnv(ani_vm* vm);
    static ani_env* AttachAniEnv(ani_vm* vm);
    static ani_object CreateAniInt(ani_env* env, int32_t status);
    static ani_object CreateAniUndefined(ani_env* env);
    static ani_object Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values);

private:
    static ani_env* env_;
    static ani_vm* vm_;
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
    void CheckRet(int32_t eventType, size_t argc, int32_t value,
        std::shared_ptr<AniBoomerangEventListener> &typeHandler);

    void ClearEventMap();
    bool RemoveAllCallback(int32_t eventType, bool isEvent);
    bool SaveCallbackByEvent(int32_t eventType, ani_ref handler, bool isOnce,
        std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> &events);
    bool IsNoExistCallback(const std::list<std::shared_ptr<AniBoomerangEventListener>> &listeners,
        ani_ref handler, int32_t eventType);
    void SaveCallback(int32_t eventType, ani_ref onHandlerRef, bool isOnce);

    static ani_env* env_;
    static ani_vm* vm_;
    ani_ref thisVarRef_ { nullptr };
    std::mutex mutex_;
    std::vector<BoomerangData> data_;
    std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> events_;
    std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> eventOnces_;
};

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif
