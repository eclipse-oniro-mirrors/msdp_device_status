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

#include "devicestatusstreambuffer_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"

#define private public
#include "devicestatus_stream_buffer.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusStreamBufferFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OHOS {
const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };
inline constexpr int32_t MAX_STREAM_BUF_SIZE { 4096 };

bool DeviceStatusStreamFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    const std::string &buf = provider.ConsumeRandomLengthString();
    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(1, MAX_STREAM_BUF_SIZE);
    StreamBuffer streamBuffer;
    int32_t n = provider.ConsumeIntegral<int32_t>();
    char *buf1 = const_cast<char*>(buf.data());
    streamBuffer.SeekReadPos(n);
    streamBuffer.Write(buf.c_str(), blobSize);
    streamBuffer.Read(buf1, blobSize);
    streamBuffer.Write(buf);
    streamBuffer.GetErrorStatusRemark();
    streamBuffer.Reset();
    streamBuffer.Clean();
    return true;
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::DeviceStatusStreamFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS