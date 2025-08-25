/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iterator>
#include <regex>
#include <vector>

#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "on_screen_data.h"
#include "on_screen_manager.h"
#include "stationary_manager.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusGetparagraphsTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
uint64_t g_tokenId = 0;
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
}

class DeviceStatusGetparagraphsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceStatusGetparagraphsTest::SetUp() {}

void DeviceStatusGetparagraphsTest::TearDown() {}

void DeviceStatusGetparagraphsTest::SetUpTestCase()
{
    const char **perms = new (std::nothrow) const char *[2];
    const char **acls = new (std::nothrow) const char *[2];
    if (perms == nullptr || acls == nullptr) {
        return;
    }
    perms[0] = PERMISSION_GET_PAGE_CONTENT;
    perms[1] = PERMISSION_SEND_CONTROL_EVENT;
    acls[0] = PERMISSION_GET_PAGE_CONTENT;
    acls[1] = PERMISSION_SEND_CONTROL_EVENT;
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .acls = acls,
        .processName = "DeviceStatusGetparagraphsTest",
        .aplStr = "system_core",
    };
    g_tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(SetSelfTokenID(g_tokenId), 0);
    AccessTokenKit::ReloadNativeTokenInfo();
}

void DeviceStatusGetparagraphsTest::TearDownTestCase()
{
    int32_t ret = AccessTokenKit::DeleteToken(g_tokenId);
    if (ret != RET_OK) {
        FI_HILOGE("failed to remove permission");
        return;
    }
}

void ConvertToWStr(const std::string& str, std::wstring& wideStr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    wideStr = converter.from_bytes(str);
}

void WStrToUtf8(const std::wstring& strIn, std::string& strOut)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    strOut = converter.to_bytes(strIn);
}

void RemovePeriods(const std::string& strIn, std::string& strOut)
{
    std::wstring wStr;
    ConvertToWStr(strIn, wStr);
    std::wstring wStrOut;
    const static std::wregex periods(L"[\n\r\t\\./;'`\\[\\]?:\\{\\}~!@#\\$-\\+，。、‘：’“”【】（）\\| ]|/n");
    std::regex_replace(std::back_inserter(wStrOut), wStr.begin(), wStr.end(), periods, L"");
    WStrToUtf8(wStrOut, strOut);
}

void AssemblyWholeText(const std::vector<OnScreen::Paragraph>& paragraphs, std::string& outputText)
{
    for (size_t idx = 0; idx < paragraphs.size(); idx++) {
        outputText += paragraphs[idx].content;
    }
}
uint64_t GetCurrentTimeStampMilliSeconds()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    return milliseconds.count();
}

/**
 * @tc.name: GetParagraphs001
 * @tc.desc: test GetParagraphs001
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusGetparagraphsTest, SendControlEvent, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreen::ContentOption option;
    option.contentUnderstand = true;
    option.pageLink = true;
    option.textOnly = true;
    OnScreen::PageContent pageContent;
    int32_t ret = OnScreen::OnScreenManager::GetInstance().GetPageContent(option, pageContent);
    if (ret != RET_OK) {
        std::cout << "ret: " << ret << std::endl;
        return;
    }
    EXPECT_TRUE(ret >= RET_ERR);
    std::string wholeTextFromParagraphs;
    AssemblyWholeText(pageContent.paragraphs, wholeTextFromParagraphs);
    std::string wholeTextFromParagraphsNoPeriod;
    RemovePeriods(wholeTextFromParagraphs, wholeTextFromParagraphsNoPeriod);
    std::string textFromContent = pageContent.title + pageContent.content;
    std::string textFromContentNoPeriod;
    RemovePeriods(textFromContent, textFromContentNoPeriod);
    std::cout << "+++++++++++++begin assembled paragraphs++++++++++++++++" << std::endl;
    std::cout << wholeTextFromParagraphsNoPeriod << std::endl;
    std::cout << "+++++++++++++end assembled paragraphs++++++++++++++++" << std::endl;
    std::cout << "+++++++++++++begin content++++++++++++++++" << std::endl;
    std::cout << textFromContentNoPeriod << std::endl;
    std::cout << "+++++++++++++end content++++++++++++++++" << std::endl;
    std::cout << "content equal to assembled paragraphs:" << std::boolalpha <<
    (wholeTextFromParagraphsNoPeriod == textFromContentNoPeriod) << std::endl;
    EXPECT_EQ(wholeTextFromParagraphsNoPeriod, textFromContentNoPeriod);
    for (size_t i = 0; i < pageContent.paragraphs.size(); i++) {
        std::cout << "------------paragraph " << i << std::endl;
        std::cout << "hookid: " << pageContent.paragraphs[i].hookId << std::endl;
        std::cout << "title: " << pageContent.paragraphs[i].title << std::endl;
        std::cout << "content: " << pageContent.paragraphs[i].content << std::endl;
        OnScreen::ControlEvent event {
            .windowId = pageContent.windowId,
            .sessionId = pageContent.sessionId,
            .hookId = pageContent.paragraphs[i].hookId,
            .eventType = OnScreen::EventType::SCROLL_TO_HOOK,
        };
        uint64_t start = GetCurrentTimeStampMilliSeconds();
        int32_t result = OnScreen::OnScreenManager::GetInstance().SendControlEvent(event);
        EXPECT_EQ(result, 0);
        uint64_t end = GetCurrentTimeStampMilliSeconds();
        std::cout << "scroll result: " << result << ", cost " << end - start << "ms" << std::endl;
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
