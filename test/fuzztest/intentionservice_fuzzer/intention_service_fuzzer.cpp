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

#include "intention_service_fuzzer.h"

#include <thread>

#include "intention_service.h"

#undef LOG_TAG
#define LOG_TAG "MsdpIntentionServiceFuzzTest"


namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

const std::vector<IIntentionIpcCode > CODE_LIST = {
    IIntentionIpcCode::COMMAND_SOCKET,
    IIntentionIpcCode::COMMAND_ENABLE_COOPERATE,
    IIntentionIpcCode::COMMAND_DISABLE_COOPERATE,
    IIntentionIpcCode::COMMAND_START_COOPERATE,
    IIntentionIpcCode::COMMAND_START_COOPERATE_WITH_OPTIONS,
    IIntentionIpcCode::COMMAND_STOP_COOPERATE,
    IIntentionIpcCode::COMMAND_REGISTER_COOPERATE_LISTENER,
    IIntentionIpcCode::COMMAND_UNREGISTER_COOPERATE_LISTENER,
    IIntentionIpcCode::COMMAND_REGISTER_HOT_AREA_LISTENER,
    IIntentionIpcCode::COMMAND_UNREGISTER_HOT_AREA_LISTENER,
    IIntentionIpcCode::COMMAND_REGISTER_MOUSE_EVENT_LISTENER,
    IIntentionIpcCode::COMMAND_UNREGISTER_MOUSE_EVENT_LISTENER,
    IIntentionIpcCode::COMMAND_GET_COOPERATE_STATE_SYNC,
    IIntentionIpcCode::COMMAND_GET_COOPERATE_STATE_ASYNC,
    IIntentionIpcCode::COMMAND_SET_DAMPLING_COEFFICIENT,
    IIntentionIpcCode::COMMAND_START_DRAG,
    IIntentionIpcCode::COMMAND_STOP_DRAG,
    IIntentionIpcCode::COMMAND_ENABLE_INTERNAL_DROP_ANIMATION,
    IIntentionIpcCode::COMMAND_ADD_DRAGLISTENER,
    IIntentionIpcCode::COMMAND_REMOVE_DRAGLISTENER,
    IIntentionIpcCode::COMMAND_ADD_SUBSCRIPT_LISTENER,
    IIntentionIpcCode::COMMAND_REMOVE_SUBSCRIPT_LISTENER,
    IIntentionIpcCode::COMMAND_SET_DRAG_WINDOW_VISIBLE,
    IIntentionIpcCode::COMMAND_UPDATE_DRAG_STYLE,
    IIntentionIpcCode::COMMAND_UPDATE_SHADOW_PIC,
    IIntentionIpcCode::COMMAND_GET_DRAG_TARGET_PID,
    IIntentionIpcCode::COMMAND_GET_UD_KEY,
    IIntentionIpcCode::COMMAND_GET_SHADOW_OFFSET,
    IIntentionIpcCode::COMMAND_GET_DRAG_DATA,
    IIntentionIpcCode::COMMAND_UPDATE_PREVIEW_STYLE,
    IIntentionIpcCode::COMMAND_UPDATE_PREVIEW_STYLE_WITH_ANIMATION,
    IIntentionIpcCode::COMMAND_ROTATE_DRAG_WINDOW_SYNC,
    IIntentionIpcCode::COMMAND_SET_DRAG_WINDOW_SCREEN_ID,
    IIntentionIpcCode::COMMAND_GET_DRAG_SUMMARY,
    IIntentionIpcCode::COMMAND_SET_DRAG_SWITCH_STATE,
    IIntentionIpcCode::COMMAND_SET_APP_DRAG_SWITCH_STATE,
    IIntentionIpcCode::COMMAND_GET_DRAG_STATE,
    IIntentionIpcCode::COMMAND_ENABLE_UPPER_CENTER_MODE,
    IIntentionIpcCode::COMMAND_GET_DRAG_ACTION,
    IIntentionIpcCode::COMMAND_GET_EXTRA_INFO,
    IIntentionIpcCode::COMMAND_ADD_PRIVILEGE,
    IIntentionIpcCode::COMMAND_ERASE_MOUSE_ICON,
    IIntentionIpcCode::COMMAND_SET_MOUSE_DRAG_MONITOR_STATE,
    IIntentionIpcCode::COMMAND_SET_DRAGGABLE_STATE,
    IIntentionIpcCode::COMMAND_GET_APP_DRAG_SWITCH_STATE,
    IIntentionIpcCode::COMMAND_SET_DRAGGABLE_STATE_ASYNC,
    IIntentionIpcCode::COMMAND_GET_DRAG_BUNDLE_INFO,
    IIntentionIpcCode::COMMAND_SUBSCRIBE_CALLBACK,
    IIntentionIpcCode::COMMAND_UNSUBSCRIBE_CALLBACK,
    IIntentionIpcCode::COMMAND_NOTIFY_METADATA_BINDING_EVENT,
    IIntentionIpcCode::COMMAND_SUBMIT_METADATA,
    IIntentionIpcCode::COMMAND_BOOMERANG_ENCODE_IMAGE,
    IIntentionIpcCode::COMMAND_BOOMERANG_DECODE_IMAGE,
    IIntentionIpcCode::COMMAND_SUBSCRIBE_STATIONARY_CALLBACK,
    IIntentionIpcCode::COMMAND_UNSUBSCRIBE_STATIONARY_CALLBACK,
    IIntentionIpcCode::COMMAND_GET_DEVICE_STATUS_DATA,
};

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS