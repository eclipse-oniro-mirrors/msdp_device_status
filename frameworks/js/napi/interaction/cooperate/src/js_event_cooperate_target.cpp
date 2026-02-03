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

#include "js_event_cooperate_target.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "interaction_manager.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "JsEventCooperateTarget"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
inline constexpr std::string_view COORDINATION { "cooperation" };
inline constexpr std::string_view CREATE_PROMISE { "napi_create_promise" };
inline constexpr std::string_view GET_UNDEFINED { "napi_get_undefined" };
inline constexpr std::string_view RESOLVE_DEFERRED { "napi_resolve_deferred" };
inline constexpr std::string_view REJECT_DEFERRED { "napi_reject_deferred" };
inline constexpr std::string_view CLOSE_SCOPE { "napi_close_handle_scope" };
std::mutex mutex_;
} // namespace

JsEventCooperateTarget::JsEventCooperateTarget()
{
    CALL_DEBUG_ENTER;
    auto ret = coordinationListeners_.insert({ COORDINATION,
        std::vector<sptr<JsUtilCooperate::CallbackInfo>>()});
    if (!ret.second) {
        FI_HILOGW("Failed to add listener, errCode:%{public}d", static_cast<int32_t>(DeviceStatus::VAL_NOT_EXP));
    }
}

void JsEventCooperateTarget::EmitJsEnable(sptr<JsUtilCooperate::CallbackInfo> cb,
    const std::string &networkId, const CoordinationMsgInfo &msgInfo)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.enableResult = (msgInfo.msg == CoordinationMessage::PREPARE ||
        msgInfo.msg == CoordinationMessage::UNPREPARE);
    cb->data.msgInfo = msgInfo;

    auto task = [cb]() {
        FI_HILOGI("Execute lambda");
        if (cb->ref == nullptr) {
            CallEnablePromiseWork(cb);
        } else {
            CallEnableAsyncWork(cb);
        }
    };
    if (napi_status::napi_ok != napi_send_event(cb->env, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void JsEventCooperateTarget::EmitJsStart(sptr<JsUtilCooperate::CallbackInfo> cb,
    const std::string &remoteNetworkId, const CoordinationMsgInfo &msgInfo)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.startResult = (msgInfo.msg == CoordinationMessage::ACTIVATE_SUCCESS);
    cb->data.msgInfo = msgInfo;

    auto task = [cb]() {
        FI_HILOGI("Execute lambda");
        if (cb->ref == nullptr) {
            CallStartPromiseWork(cb);
        } else {
            CallStartAsyncWork(cb);
        }
    };
    if (napi_status::napi_ok != napi_send_event(cb->env, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void JsEventCooperateTarget::EmitJsStop(sptr<JsUtilCooperate::CallbackInfo> cb,
    const std::string &networkId, const CoordinationMsgInfo &msgInfo)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.stopResult = (msgInfo.msg == CoordinationMessage::DEACTIVATE_SUCCESS);
    cb->data.msgInfo = msgInfo;

    auto task = [cb]() {
        FI_HILOGI("Execute lambda");
        if (cb->ref == nullptr) {
            CallStopPromiseWork(cb);
        } else {
            CallStopAsyncWork(cb);
        }
    };
    if (napi_status::napi_ok != napi_send_event(cb->env, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void JsEventCooperateTarget::EmitJsGetState(sptr<JsUtilCooperate::CallbackInfo> cb, bool state)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.coordinationOpened = state;

    auto task = [cb]() {
        FI_HILOGI("Execute lambda");
        if (cb->ref == nullptr) {
            CallGetStatePromiseWork(cb);
        } else {
            CallGetStateAsyncWork(cb);
        }
    };
    if (napi_status::napi_ok != napi_send_event(cb->env, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void JsEventCooperateTarget::AddListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = coordinationListeners_.find(type);
    if (iter == coordinationListeners_.end()) {
        FI_HILOGE("Failed to add listener, type:%{public}s", type.c_str());
        return;
    }

    for (const auto &item : iter->second) {
        CHKPC(item);
        if (JsUtilCooperate::IsSameHandle(env, handle, item->ref)) {
            FI_HILOGE("The handle already exists");
            return;
        }
    }
    napi_ref ref = nullptr;
    CHKRV(napi_create_reference(env, handle, 1, &ref), CREATE_REFERENCE);
    sptr<JsUtilCooperate::CallbackInfo> monitor = new (std::nothrow) JsUtilCooperate::CallbackInfo();
    CHKPV(monitor);
    monitor->env = env;
    monitor->ref = ref;
    iter->second.push_back(std::move(monitor));
    if (!isListeningProcess_) {
        isListeningProcess_ = true;
        INTERACTION_MGR->RegisterCoordinationListener(shared_from_this());
    }
}

void JsEventCooperateTarget::RemoveListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = coordinationListeners_.find(type);
    if (iter == coordinationListeners_.end()) {
        FI_HILOGE("Failed to remove listener, type:%{public}s", type.c_str());
        return;
    }
    if (handle == nullptr) {
        iter->second.clear();
        goto monitorTag;
    }
    for (auto it = iter->second.begin(); it != iter->second.end(); ++it) {
        if (JsUtilCooperate::IsSameHandle(env, handle, (*it)->ref)) {
            FI_HILOGE("Successfully removed the listener");
            iter->second.erase(it);
            goto monitorTag;
        }
    }

monitorTag:
    if (isListeningProcess_ && iter->second.empty()) {
        isListeningProcess_ = false;
        INTERACTION_MGR->UnregisterCoordinationListener(shared_from_this());
    }
}

napi_value JsEventCooperateTarget::CreateCallbackInfo(napi_env env,
    napi_value handle, sptr<JsUtilCooperate::CallbackInfo> callback)
{
    CALL_INFO_TRACE;
    CHKPP(callback);
    callback->env = env;
    napi_value promise = nullptr;
    if (handle == nullptr) {
        CHKRP(napi_create_promise(env, &callback->deferred, &promise), CREATE_PROMISE);
    } else {
        CHKRP(napi_create_reference(env, handle, 1, &callback->ref), CREATE_REFERENCE);
    }
    return promise;
}

void JsEventCooperateTarget::ResetEnv()
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    INTERACTION_MGR->UnregisterCoordinationListener(shared_from_this());
}

void JsEventCooperateTarget::OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = coordinationListeners_.find(COORDINATION);
    if (changeEvent == coordinationListeners_.end()) {
        FI_HILOGE("Failed to find the %{public}s", std::string(COORDINATION).c_str());
        return;
    }

    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env);
        item->data.msgInfo.msg = msg;
        item->data.deviceDescriptor = networkId;
        item->IncStrongRef(nullptr);
        auto task = [item]() {
            FI_HILOGI("Execute lamdba");
            EmitCoordinationMessageEvent(item);
        };
        if (napi_status::napi_ok != napi_send_event(item->env, task, napi_eprio_immediate)) {
            FI_HILOGE("Failed to SendEvent");
        }
    }
}

void JsEventCooperateTarget::CallEnablePromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Enable promise, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Enable promise, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetEnableInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Enable promise, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(cb->env, object, &valueType) != napi_ok) {
        FI_HILOGE("Enable promise, napi typeof failed");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    if (valueType != napi_undefined) {
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, object), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    }
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::CallEnableAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Enable async, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Enable async, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetEnableInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Enable async, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value processor = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &processor), GET_REFERENCE_VALUE, scope);
    napi_value ret = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, processor, 1, &object, &ret), CALL_FUNCTION, scope);
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::CallStartPromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Start promise, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Start promise, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetStartInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Start promise, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_valuetype napiValueType = napi_undefined;
    if (napi_typeof(cb->env, object, &napiValueType) != napi_ok) {
        FI_HILOGE("Start promise, napi typeof failed");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    if (napiValueType != napi_undefined) {
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, object), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    }
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::CallStartAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Start async, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Start async, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetStartInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Start async, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value napiHandler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &napiHandler), GET_REFERENCE_VALUE, scope);
    napi_value ret = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, napiHandler, 1, &object, &ret), CALL_FUNCTION, scope);
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::CallStopPromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Stop promise, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope napiHandleScope = nullptr;
    napi_open_handle_scope(cb->env, &napiHandleScope);
    if (napiHandleScope == nullptr) {
        FI_HILOGE("Stop promise, napiHandleScope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetStopInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Stop promise, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, napiHandleScope);
        return;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(cb->env, object, &valueType) != napi_ok) {
        FI_HILOGE("Stop promise, napi typeof failed");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, napiHandleScope);
        return;
    }
    if (valueType != napi_undefined) {
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, object), REJECT_DEFERRED, napiHandleScope);
    } else {
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, napiHandleScope);
    }
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, napiHandleScope);
}

void JsEventCooperateTarget::CallStopAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Stop async, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Stop async, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetStopInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Stop async, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value napiHandler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &napiHandler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, napiHandler, 1, &object, &result), CALL_FUNCTION, scope);
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::CallGetStatePromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Get start promise, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Get start promise, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value object = JsUtilCooperate::GetStateInfo(cb);
    if (object == nullptr) {
        FI_HILOGE("Get start promise, object is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::CallGetStateAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("Get start async, check data is nullptr");
        return;
    }
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        FI_HILOGE("Get start async, scope is nullptr");
        RELEASE_CALLBACKINFO(cb->env, cb->ref);
        return;
    }
    napi_value resultObj[2];
    CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &resultObj[0]), GET_UNDEFINED, scope);
    resultObj[1] = JsUtilCooperate::GetStateInfo(cb);
    if (resultObj[1] == nullptr) {
        FI_HILOGE("Get start async, object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value handlerInfo = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handlerInfo), GET_REFERENCE_VALUE, scope);
    napi_value ret = nullptr;
    size_t argc = TWO_PARAM;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handlerInfo, argc, resultObj, &ret),
        CALL_FUNCTION, scope);
    RELEASE_CALLBACKINFO(cb->env, cb->ref);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventCooperateTarget::EmitCoordinationMessageEvent(sptr<JsUtilCooperate::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
    if (cb == nullptr) {
        FI_HILOGE("The data is nullptr");
        return;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    auto msgEvent = coordinationListeners_.find(COORDINATION);
    if (msgEvent == coordinationListeners_.end()) {
        FI_HILOGE("Failed to find the msgEvent");
        return;
    }
    for (const auto &item : msgEvent->second) {
        if (item == nullptr) {
            FI_HILOGE("item is nullptr");
            continue;
        }
        CHKPC(item->env);
        if (item->ref != cb->ref) {
            continue;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        napi_value deviceDescriptor = nullptr;
        CHKRV_SCOPE(item->env, napi_create_string_utf8(item->env, item->data.deviceDescriptor.c_str(),
            NAPI_AUTO_LENGTH, &deviceDescriptor), CREATE_STRING_UTF8, scope);
        napi_value eventMsg = nullptr;
        auto iter = messageTransform.find(item->data.msgInfo.msg);
        if (iter == messageTransform.end()) {
            FI_HILOGE("Failed to find the message code");
            CHKRV(napi_close_handle_scope(item->env, scope), CLOSE_SCOPE);
            return;
        }
        CHKRV_SCOPE(item->env, napi_create_int32(item->env, static_cast<int32_t>(iter->second), &eventMsg),
            CREATE_INT32, scope);
        napi_value object = nullptr;
        CHKRV_SCOPE(item->env, napi_create_object(item->env, &object), CREATE_OBJECT, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "deviceDescriptor", deviceDescriptor),
            SET_NAMED_PROPERTY, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "eventMsg", eventMsg),
            SET_NAMED_PROPERTY, scope);
        napi_value handler = nullptr;
        CHKRV_SCOPE(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE_VALUE, scope);
        napi_value ret = nullptr;
        CHKRV_SCOPE(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret), CALL_FUNCTION, scope);
        napi_close_handle_scope(item->env, scope);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
