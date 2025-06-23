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
#include "room_location_event_napi.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "RoomLocationEventNapi"

namespace OHOS {
namespace Msdp {
RoomLocationEventNapi::RoomLocationEventNapi(napi_env env, napi_value thisVar)
{
    std::lock_guard<std::mutex> lock(mutex_);
    env_ = env;
    thisVarRef_ = nullptr;
    napi_status status = napi_create_reference(env, thisVar, 1, &thisVarRef_);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create the reference");
        return;
    }
}

RoomLocationEventNapi::~RoomLocationEventNapi()
{
    FI_HILOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    napi_status status = napi_delete_reference(env_, thisVarRef_);
    if (status != napi_ok) {
        FI_HILOGE("Failed to delete the reference");
        return;
    }
}

void RoomLocationEventNapi::ClearEnv()
{
    FI_HILOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    roomEventMap_.clear();
}

void RoomLocationEventNapi::UpdateEnv(napi_env env, napi_value jsThis)
{
    FI_HILOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    env_ = env;
    napi_create_reference(env, jsThis, 1, &thisVarRef_);
    FI_HILOGI("Exit");
}

bool RoomLocationEventNapi::AddCallback(const std::string pkgName, napi_value handler)
{
    FI_HILOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    packageName_ = pkgName;
    auto iter = roomEventMap_.find(pkgName);
    if (iter == roomEventMap_.end()) {
        FI_HILOGI("not found pkgName: %{public}s", pkgName.c_str());
        napi_ref newHandlerRef = nullptr;
        napi_status status = napi_create_reference(env_, handler, 1, &newHandlerRef);
        if (status != napi_ok || newHandlerRef == nullptr) {
            FI_HILOGE("napi_create_reference failed");
            return false;
        }
        auto listener = std::make_shared<RoomLocationEventListener>();
        listener->handlerRef = newHandlerRef;
        roomEventMap_.insert(std::make_pair(pkgName, listener));
        FI_HILOGI("Insert finish");
        return true;
    }
    FI_HILOGI("find pkgName: %{public}s", pkgName.c_str());
    if (iter->second == nullptr || iter->second->handlerRef == nullptr) {
        FI_HILOGE("listener or handlerRef is nullptr");
        roomEventMap_.erase(iter);
        return false;
    }
    FI_HILOGI("check pkgName: %{public}s same handle", pkgName.c_str());
    if (!InsertRef(iter->second, handler)) {
        FI_HILOGE("Failed to insert ref");
        roomEventMap_.erase(iter);
        return false;
    }
    return true;
}

bool RoomLocationEventNapi::InsertRef(
    std::shared_ptr<RoomLocationEventListener> listener, const napi_value &handler)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    napi_value onHandler = nullptr;
    napi_status status = napi_get_reference_value(env_, listener->handlerRef, &onHandler);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_reference_value failed");
        status = napi_delete_reference(env_, listener->handlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
        return false;
    }
    if (IsSameValue(env_, handler, onHandler)) {
        return true;
    }
    napi_ref handlerRef = nullptr;
    status = napi_create_reference(env_, handler, 1, &handlerRef);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_reference failed");
        return false;
    }
    FI_HILOGD("Insert new ref");
    listener->handlerRef = handlerRef;
    return true;
}

bool RoomLocationEventNapi::IsSameValue(const napi_env &env,
    const napi_value &lhs, const napi_value &rhs)
{
    FI_HILOGD("Enter");
    bool result = false;
    napi_status status = napi_strict_equals(env, lhs, rhs, &result);
    if (status != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
    }
    return result;
}

void RoomLocationEventNapi::RemoveCallback(const std::string pkgName)
{
    FI_HILOGI("Enter, pkgName: %{public}s", pkgName.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = roomEventMap_.find(pkgName);
    if (iter == roomEventMap_.end()) {
        FI_HILOGE("pkgName %{public}s not found", pkgName.c_str());
        return;
    }
    if (iter->second == nullptr || iter->second->handlerRef == nullptr) {
        FI_HILOGE("listener or handlerRef is nullptr");
        roomEventMap_.erase(iter);
        return;
    }

    napi_status status = napi_delete_reference(env_, iter->second->handlerRef);
    if (status != napi_ok) {
        FI_HILOGE("napi_delete_reference failed");
    }
    roomEventMap_.erase(iter);
    return;
}

void RoomLocationEventNapi::OnRoomEvent(size_t argc, const napi_value *argv)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (roomEventMap_.empty()) {
        FI_HILOGE("roomEventMap_ is empty");
        return;
    }
    auto iter = roomEventMap_.find(packageName_);
    if (iter == roomEventMap_.end()) {
        FI_HILOGE("pkgName: %{public}s not found", packageName_.c_str());
        return;
    }
    if (iter->second == nullptr || iter->second->handlerRef == nullptr) {
        FI_HILOGE("listener or handlerRef is nullptr");
        return;
    }
    napi_value handler = nullptr;
    napi_status ret = napi_get_reference_value(env_, iter->second->handlerRef, &handler);
    if (ret != napi_ok) {
        FI_HILOGE("napi_get_reference_value for %{public}s failed, status: %{public}d",
            packageName_.c_str(), ret);
        return;
    }

    napi_value callResult = nullptr;
    if (napi_call_function(env_, nullptr, handler, argc, argv, &callResult) != napi_ok) {
        FI_HILOGE("napi_call_function failed");
    }
}
} // namespace Msdp
} // namespace OHOS
