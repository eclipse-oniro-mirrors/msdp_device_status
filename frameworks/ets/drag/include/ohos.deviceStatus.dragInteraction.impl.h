/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DEVICESTATUS_DRAG_INTERACTION_H
#define OHOS_DEVICESTATUS_DRAG_INTERACTION_H

#include "devicestatus_define.h"
#include "interaction_manager.h"
#include "ohos.deviceStatus.dragInteraction.proj.hpp"
#include "ohos.deviceStatus.dragInteraction.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <algorithm>
#include <mutex>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace {
using namespace taihe;
using namespace ohos::deviceStatus::dragInteraction;
using namespace OHOS::Msdp;

using callbackType = std::variant<taihe::callback<void(DragState)>>;
struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref)
    {
    }
    ~CallbackObject()
    {
    }
    void Release()
    {
        taihe::env_guard guard;
        if (auto *env = guard.get_env()) {
            env->GlobalReference_Delete(ref);
        }
    }
    callbackType callback;
    ani_ref ref;
};

class EtsDragManager : public DeviceStatus::IDragListener, public std::enable_shared_from_this<EtsDragManager> {
public:
    EtsDragManager() = default;
    DISALLOW_COPY_AND_MOVE(EtsDragManager);
    ~EtsDragManager() = default;

    void registerListener(callback_view<void(ohos::deviceStatus::dragInteraction::DragState)> callback, uintptr_t opq);
    void unRegisterListener(optional_view<uintptr_t> opq);
    void OnDragMessage(DeviceStatus::DragState state) override;
    array<Summary> getDataSummary();

    static std::shared_ptr<EtsDragManager> GetInstance();

private:
    std::atomic_bool hasRegistered_ { false };
    std::mutex mutex_;
    std::map<std::string, std::vector<std::unique_ptr<CallbackObject>>> jsCbMap_;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};
} // namespace
#endif // OHOS_DEVICESTATUS_DRAG_INTERACTION_H