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

#ifndef ONSCREEN_NAPI_H
#define ONSCREEN_NAPI_H

#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "on_screen_data.h"
#include "on_screen_manager.h"
#include "on_screen_napi_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenNapi {
public:
    explicit OnScreenNapi(napi_env env, napi_value thisVar);
    ~OnScreenNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value GetPageContentNapi(napi_env env, napi_callback_info info);
    static napi_value SendControlEventNapi(napi_env env, napi_callback_info info);

private:
    static bool ConstructOnScreen(napi_env env, napi_value jsThis);
    static bool GetContentOption(napi_env env, napi_value *args, size_t argc, ContentOption &option);
    static bool GetControlEvent(napi_env env, napi_value *args, size_t argc, ControlEvent &event);
    // utils
    static bool SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static bool SetInt64Property(napi_env env, napi_value targetObj, int64_t value, const char *propName);
    static bool SetStringProperty(napi_env env, napi_value targetObj, const std::string &value, const char *propName);
    static bool ConstructParagraphObj(napi_env env, napi_value retObj, const Paragraph &value);
    static bool SetParagraphVecProperty(napi_env env, napi_value targetObj, const std::vector<Paragraph> paragraphs,
        const char *propName);
    static bool GetInt32FromJs(napi_env env, const napi_value &value, const std::string &field, int32_t &result, bool isNecessary)
    static bool GetInt64FromJs(napi_env env, const napi_value &value, const std::string &field, int64_t &result, bool isNecessary);
    static bool GetBoolFromJs(napi_env env, const napi_value &value, const std::string &field, bool &result, bool isNecessary);
    static bool SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
    // GetPageContent
    static bool GetPageContentExec(GetPageContentAsyncContext *asyncContext);
    static void GetPageContentExecCB(napi_env env, void *data);
    static void GetPageContentCompCB(napi_env env, napi_status status, void *data);
    // SendControlEvent
    static bool SendControlEventExec(GetPageContentAsyncContext *asyncContext);
    static void SendControlEventExecCB(napi_env env, void *data);
    static void SendControlEventCompCB(napi_env env, napi_status status, void *data);
    
    napi_env env_;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ONSCREEN_NAPI_H