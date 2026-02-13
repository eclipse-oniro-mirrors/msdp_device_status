/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
 
#include "universal_drag_wrapper.h"
 
#include <dlfcn.h>

#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "UniversalDragWrapper"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string UNIVERSAL_DRAG_MANAGER_SO_PATH = "/system/lib64/libuniversal_drag.z.so";
}

bool UniversalDragWrapper::InitUniversalDrag()
{
    FI_HILOGI("Enter InitUniversalDrag");
    universalDragHandle_ = dlopen(UNIVERSAL_DRAG_MANAGER_SO_PATH.c_str(), RTLD_LAZY);
    char *error = nullptr;
    if (((error = dlerror()) != nullptr) || (universalDragHandle_ == nullptr)) {
        FI_HILOGE("Couldn't load universal drag handler library with dlopen(). Error: %{public}s", error);
        return false;
    }
    if (initUniversalDragHandle_ == nullptr) {
        initUniversalDragHandle_ =
            reinterpret_cast<InitFunc>(dlsym(universalDragHandle_, "Init"));
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol Init error: %{public}s", error);
            return false;
        }
    }
    if (initUniversalDragHandle_ == nullptr) {
        FI_HILOGE("initUniversalDragHandle_ is null");
        return false;
    }
    return initUniversalDragHandle_(env_);
}

void UniversalDragWrapper::RemoveUniversalDrag()
{
    FI_HILOGI("Enter RemoveUniversalDrag");
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return;
    }
    if (removeUniversalDragHandle_ == nullptr) {
        removeUniversalDragHandle_ =
            reinterpret_cast<RemoveUniversalDragFunc>(dlsym(universalDragHandle_, "RemoveUniversalDrag"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol RemoveUniversalDrag error: %{public}s", error);
            return;
        }
    }
    if (removeUniversalDragHandle_ != nullptr) {
        removeUniversalDragHandle_();
        FI_HILOGI("RemoveUniversalDrag success");
    }
}

void UniversalDragWrapper::SetDragableState(bool state)
{
    CALL_DEBUG_ENTER;
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return;
    }
    if (setDragableStateHandle_ == nullptr) {
        setDragableStateHandle_ =
            reinterpret_cast<SetDragableStateFunc>(dlsym(universalDragHandle_, "SetDragableState"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol SetDragableState error: %{public}s", error);
            return;
        }
    }
    if (setDragableStateHandle_ != nullptr) {
        setDragableStateHandle_(state);
    }
}

int32_t UniversalDragWrapper::GetAppDragSwitchState(const std::string &pkgName, bool &state)
{
    CALL_DEBUG_ENTER;
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return RET_ERR;
    }
    if (getAppDragSwitchStateHandle_ == nullptr) {
        getAppDragSwitchStateHandle_ =
            reinterpret_cast<GetAppDragSwitchStateFunc>(dlsym(universalDragHandle_, "GetAppDragSwitchState"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol GetAppDragSwitchState error: %{public}s", error);
            return RET_ERR;
        }
    }

    if (getAppDragSwitchStateHandle_ == nullptr) {
        FI_HILOGE("getAppDragSwitchStateHandle_ is null");
        return RET_ERR;
    }
    return getAppDragSwitchStateHandle_(pkgName.c_str(), state);
}

void UniversalDragWrapper::SetDraggableStateAsync(bool state, int64_t downTime)
{
    CALL_DEBUG_ENTER;
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return;
    }
    if (setDraggableStateAsyncHandle_ == nullptr) {
        setDraggableStateAsyncHandle_ =
            reinterpret_cast<SetDraggableStateAsyncFunc>(dlsym(universalDragHandle_, "SetDraggableStateAsync"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol SetDraggableStateAsync error: %{public}s", error);
            return;
        }
    }

    if (setDraggableStateAsyncHandle_ == nullptr) {
        FI_HILOGE("setDraggableStateAsyncHandle_ is null");
        return;
    }
    setDraggableStateAsyncHandle_(state, downTime);
}

UniversalDragWrapper::~UniversalDragWrapper()
{
    FI_HILOGI("Destructor success");
    if (universalDragHandle_ != nullptr) {
        dlclose(universalDragHandle_);
        universalDragHandle_ = nullptr;
        FI_HILOGW("Remove universalDragHandle success");
    }
    initUniversalDragHandle_ = nullptr;
    removeUniversalDragHandle_ = nullptr;
    setDragableStateHandle_ = nullptr;
    setDragSwitchStateHandle_ = nullptr;
    setAppDragSwitchStateHandle_ = nullptr;
    getAppDragSwitchStateHandle_ = nullptr;
    setDraggableStateAsyncHandle_ = nullptr;
    StopLongPressDragHandle_ = nullptr;
}

void UniversalDragWrapper::SetDragSwitchState(bool enable)
{
    CALL_DEBUG_ENTER;
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return;
    }
    if (setDragSwitchStateHandle_ == nullptr) {
        setDragSwitchStateHandle_ =
            reinterpret_cast<SetDragSwitchStateFunc>(dlsym(universalDragHandle_, "SetDragSwitchState"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol SetDragSwitchState error: %{public}s", error);
            return;
        }
    }
    if (setDragSwitchStateHandle_ != nullptr) {
        setDragSwitchStateHandle_(enable);
    }
}
 
void UniversalDragWrapper::SetAppDragSwitchState(const std::string &pkgName, bool enable)
{
    CALL_DEBUG_ENTER;
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return;
    }
    if (setAppDragSwitchStateHandle_ == nullptr) {
        setAppDragSwitchStateHandle_ =
            reinterpret_cast<SetAppDragSwitchStateFunc>(dlsym(universalDragHandle_, "SetAppDragSwitchState"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol SetAppDragSwitchState error: %{public}s", error);
            return;
        }
    }
    if (setAppDragSwitchStateHandle_ != nullptr) {
        setAppDragSwitchStateHandle_(pkgName.c_str(), enable);
    }
}

void UniversalDragWrapper::StopLongPressDrag()
{
    CALL_DEBUG_ENTER;
    if (universalDragHandle_ == nullptr) {
        FI_HILOGE("universalDragHandle_ is null");
        return;
    }
    if (StopLongPressDragHandle_ == nullptr) {
        StopLongPressDragHandle_ =
            reinterpret_cast<StopLongPressDragFunc>(dlsym(universalDragHandle_, "StopLongPressDrag"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol StopLongPressDrag error: %{public}s", error);
            return;
        }
    }
    if (StopLongPressDragHandle_ != nullptr) {
        StopLongPressDragHandle_();
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS