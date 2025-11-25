/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_drag_manager.h"

#include "devicestatus_define.h"
#include "interaction_manager.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "JsDragManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void JsDragManager::ResetEnv()
{
    CALL_INFO_TRACE;
}

bool JsDragManager::IsSameHandle(napi_env env, napi_value handle, napi_ref ref)
{
    CALL_INFO_TRACE;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHKPF(scope);
    napi_value handlerTemp = nullptr;
    CHKRF_SCOPE(env, napi_get_reference_value(env, ref, &handlerTemp), GET_REFERENCE_VALUE, scope);
    bool isEqual = false;
    CHKRF_SCOPE(env, napi_strict_equals(env, handle, handlerTemp, &isEqual), STRICT_EQUALS, scope);
    napi_close_handle_scope(env, scope);
    return isEqual;
}

napi_value JsDragManager::GetDataSummary(napi_env env)
{
    CALL_INFO_TRACE;
    napi_value arr = nullptr;
    CHKRP(napi_create_array(env, &arr), CREATE_ARRAY);
    std::map<std::string, int64_t> summarys;
    if (INTERACTION_MGR->GetDragSummary(summarys, true) != RET_OK) {
        FI_HILOGE("Failed to GetDragSummary");
        return arr;
    }
    uint32_t index = 0;
    for (const auto &summary : summarys) {
        napi_value dataType = nullptr;
        CHKRP(napi_create_string_utf8(env, summary.first.c_str(), NAPI_AUTO_LENGTH, &dataType), CREATE_STRING_UTF8);
        napi_value dataSize = nullptr;
        CHKRP(napi_create_int64(env, summary.second, &dataSize), CREATE_INT64);
        napi_value object = nullptr;
        CHKRP(napi_create_object(env, &object), CREATE_OBJECT);
        CHKRP(napi_set_named_property(env, object, "dataType", dataType), SET_NAMED_PROPERTY);
        CHKRP(napi_set_named_property(env, object, "dataSize", dataSize), SET_NAMED_PROPERTY);
        CHKRP(napi_set_element(env, arr, index, object), SET_ELEMENT);
        ++index;
    }
    return arr;
}

int32_t JsDragManager::SetDragSwitchState(napi_env env, bool enable)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    return INTERACTION_MGR->SetDragSwitchState(enable, true);
}

int32_t JsDragManager::SetAppDragSwitchState(napi_env env, bool enable, const std::string &pkgName)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    if (pkgName.empty()) {
        FI_HILOGE("The pkgName is empty");
        return COMMON_PARAMETER_ERROR;
    }
    return INTERACTION_MGR->SetAppDragSwitchState(enable, pkgName, true);
}

void JsDragManager::RegisterListener(napi_env env, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : listeners_) {
        CHKPC(item);
        if (item->env == env && IsSameHandle(env, handle, item->ref)) {
            FI_HILOGE("The handle already exists");
            return;
        }
    }
    napi_ref ref = nullptr;
    CHKRV(napi_create_reference(env, handle, 1, &ref), CREATE_REFERENCE);
    sptr<CallbackInfo> monitor = new (std::nothrow) CallbackInfo();
    CHKPV(monitor);
    monitor->env = env;
    monitor->ref = ref;
    listeners_.push_back(std::move(monitor));
    if (!hasRegistered_) {
        hasRegistered_ = true;
        INTERACTION_MGR->AddDraglistener(shared_from_this(), true);
    }
}

void JsDragManager::UnregisterListener(napi_env env, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    if (listeners_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }
    for (auto iter = listeners_.begin(); iter != listeners_.end();) {
        if (handle == nullptr) {
            RELEASE_CALLBACKINFO((*iter)->env, (*iter)->ref);
            iter = listeners_.erase(iter);
        } else {
            if ((*iter)->env == env && IsSameHandle(env, handle, (*iter)->ref)) {
                FI_HILOGD("Removing monitor successfully");
                RELEASE_CALLBACKINFO((*iter)->env, (*iter)->ref);
                iter = listeners_.erase(iter);
                break;
            }
            ++iter;
        }
    }
    if (hasRegistered_ && listeners_.empty()) {
        hasRegistered_ = false;
        INTERACTION_MGR->RemoveDraglistener(shared_from_this(), true);
    }
}

void JsDragManager::OnDragMessage(DragState state)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (listeners_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }
    for (auto &item : listeners_) {
        CHKPC(item);
        CHKPC(item->env);
        item->state = state;
        item->IncStrongRef(nullptr);

        auto task = [item]() {
            FI_HILOGI("Execute lamdba");
            CallDragMsg(item);
        };
        if (napi_status::napi_ok != napi_send_event(item->env, task, napi_eprio_immediate)) {
            FI_HILOGE("Failed to SendEvent");
        }
    }
}

void JsDragManager::CallDragMsg(sptr<CallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("Check data is nullptr");
        return;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (listeners_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }
    for (const auto &item : listeners_) {
        CHKPC(item->env);
        if (item->ref != cb->ref) {
            continue;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        CHKPC(scope);
        napi_value stateMsg = nullptr;
        CHKRV_SCOPE(item->env, napi_create_int32(item->env, static_cast<int32_t>(item->state), &stateMsg),
            CREATE_INT32, scope);
        napi_value handler = nullptr;
        CHKRV_SCOPE(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE_VALUE, scope);
        napi_value ret = nullptr;
        CHKRV_SCOPE(item->env,
            napi_call_function(item->env, nullptr, handler, 1, &stateMsg, &ret), CALL_FUNCTION, scope);
        napi_close_handle_scope(item->env, scope);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
