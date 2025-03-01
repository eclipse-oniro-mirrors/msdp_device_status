/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BOOMERANG_DUMPER_H
#define BOOMERANG_DUMPER_H

#include <string>
#include <vector>

#include "i_context.h"
#include "boomerang_server.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangDumper final {
public:
    BoomerangDumper(IContext *env, BoomerangServer &boomerang) : env_(env), boomerang_(boomerang) {}
    ~BoomerangDumper() = default;
    DISALLOW_COPY_AND_MOVE(BoomerangDumper);

    void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    void DumpOnce(int32_t fd, int32_t option);
    void DumpHelpInfo(int32_t fd) const;
    void DumpDeviceStatusSubscriber(int32_t fd) const;
    void DumpDeviceStatusChanges(int32_t fd) const;
    void DumpCurrentDeviceStatus(int32_t fd);
    void DumpDrag(int32_t fd) const;
    void DumpCheckDefine(int32_t fd) const;

    template<class ...Ts>
    void CheckDefineOutput(int32_t fd, const char* fmt, Ts... args) const;

    IContext *env_ { nullptr };
    BoomerangServer &boomerang_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_DUMPER_H