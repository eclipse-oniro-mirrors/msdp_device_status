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

#ifndef ON_SCREEN_SERVER_H
#define ON_SCREEN_SERVER_H

#include <mutex>

#include "i_on_screen_algorithm.h"
#include "i_plugin.h"
#include "on_screen_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
struct OnScreenAlgorithmHandle {
    OnScreenAlgorithmHandle() : handle(nullptr), pAlgorithm(nullptr), create(nullptr), destroy(nullptr) {}
    ~OnScreenAlgorithmHandle();
    void Clear();
    void* handle = nullptr;
    IOnScreenAlgorithm* pAlgorithm = nullptr;
    IOnScreenAlgorithm* (*create)();
    void (*destroy)(const IOnScreenAlgorithm*);
};

class OnScreenServer {
public:
    OnScreenServer() = default;
    virtual ~OnScreenServer();
    int32_t GetPageContent(const CallingContext &context, const ContentOption &option, PageContent &pageContent);
    int32_t SendControlEvent(const CallingContext &context, const ControlEvent &event);
private:
    int32_t LoadAlgoLib();
    int32_t UnloadAlgoLib();
    int32_t ConnectAlgoLib();
    int32_t CheckPermission(const CallingContext &context, const std::string &permission);

    OnScreenAlgorithmHandle handle_;
    std::mutex mtx_;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ON_SCREEN_SERVER_H